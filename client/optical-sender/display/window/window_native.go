// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

//go:build nativewindow

package window

import (
	"context"
	"errors"
	"fmt"
	"image"
	"image/color"
	"io"
	"sync/atomic"
	"time"

	"github.com/hajimehoshi/ebiten/v2"
	"github.com/hajimehoshi/ebiten/v2/ebitenutil"
	"github.com/hajimehoshi/ebiten/v2/inpututil"

	"github.com/wojciechpolak/dud/client/optical-sender"
	"github.com/wojciechpolak/dud/client/optical-sender/display"
)

type displayStats struct {
	generated atomic.Uint64
	displayed atomic.Uint64
	missed    atomic.Uint64
	started   time.Time
}

type displayGame struct {
	width       int
	current     *ebiten.Image
	frames      <-chan display.Frame
	stats       *displayStats
	title       windowTitle
	startButton image.Rectangle
	start       func() <-chan display.Frame
	ctx         context.Context
	pacer       *display.Pacer
	started     bool
	repeating   bool
	redraw      bool
}

func startProducer(ctx context.Context, encoder *optical.Encoder, scheduler *display.Scheduler, settings display.QRSettings, qrSymbols int, generated func()) <-chan display.Frame {
	frames := make(chan display.Frame, 2)
	go func() {
		defer close(frames)
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			frame := display.RenderNext(encoder, scheduler, settings, qrSymbols)
			generated()
			select {
			case frames <- frame:
			case <-ctx.Done():
				return
			}
			if frame.Err != nil {
				return
			}
		}
	}()
	return frames
}

func RunWindow(encoder *optical.Encoder, scheduler *display.Scheduler, settings display.QRSettings, first display.Frame, qrSymbols, fps int, errorsOutput io.Writer) error {
	return RunWindowContext(context.Background(), encoder, scheduler, settings, first, qrSymbols, fps, errorsOutput)
}

func RunWindowContext(parent context.Context, encoder *optical.Encoder, scheduler *display.Scheduler, settings display.QRSettings, first display.Frame, qrSymbols, fps int, errorsOutput io.Writer) error {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	stats := &displayStats{}
	buttonWidth := 220
	buttonHeight := 48
	game := &displayGame{
		width:     first.Raster.Bounds().Dx(),
		ctx:       ctx,
		current:   ebiten.NewImageFromImage(first.Raster),
		stats:     stats,
		title:     newWindowTitle(settings, encoder.BlockSize(), qrSymbols, fps),
		repeating: display.RepeatableFrame(first),
		redraw:    true,
	}
	game.startButton = image.Rect((game.width-buttonWidth)/2, game.width/2+28, (game.width+buttonWidth)/2, game.width/2+28+buttonHeight)
	game.start = func() <-chan display.Frame {
		stats.started = time.Now()
		game.pacer = display.NewPacer(stats.started, fps)
		stats.generated.Store(1)
		stats.displayed.Store(1)
		if game.repeating {
			fmt.Fprintln(errorsOutput, "Single-block capsule: every QR symbol contains the complete ciphertext; keeping the prepared display. Press Q or Escape to stop it.")
			return nil
		}
		return startProducer(ctx, encoder, scheduler, settings, qrSymbols, func() { stats.generated.Add(1) })
	}
	ebiten.SetTPS(fps)
	ebiten.SetVsyncEnabled(true)
	ebiten.SetScreenClearedEveryFrame(false)
	ebiten.SetWindowResizingMode(ebiten.WindowResizingModeDisabled)
	ebiten.SetWindowSize(game.width, game.width)
	ebiten.SetWindowTitle(game.title.ready())
	err := ebiten.RunGame(game)
	cancel()
	if game.frames != nil {
		for range game.frames {
		}
	}
	game.current.Dispose()
	elapsed := 0.0
	if game.started {
		elapsed = time.Since(stats.started).Seconds()
	}
	fmt.Fprintf(errorsOutput, "Display stopped: generated-display-frames=%d displayed-display-frames=%d qr-symbols-per-frame=%d missed-ticks=%d elapsed=%.3fs\n", stats.generated.Load(), stats.displayed.Load(), qrSymbols, stats.missed.Load(), elapsed)
	return err
}

func (g *displayGame) Update() error {
	select {
	case <-g.ctx.Done():
		return ebiten.Termination
	default:
	}
	if inpututil.IsKeyJustPressed(ebiten.KeyEscape) || inpututil.IsKeyJustPressed(ebiten.KeyQ) {
		return ebiten.Termination
	}
	if !g.started {
		mouseStarted := false
		if inpututil.IsMouseButtonJustPressed(ebiten.MouseButtonLeft) {
			x, y := ebiten.CursorPosition()
			mouseStarted = image.Pt(x, y).In(g.startButton)
		}
		if inpututil.IsKeyJustPressed(ebiten.KeySpace) || inpututil.IsKeyJustPressed(ebiten.KeyEnter) || mouseStarted {
			g.started = true
			g.redraw = true
			g.frames = g.start()
			ebiten.SetWindowTitle(g.title.begin(g.stats.started))
		}
		return nil
	}
	now := time.Now()
	if title, changed := g.title.tick(now); changed {
		ebiten.SetWindowTitle(title)
	}
	if g.repeating {
		return nil
	}
	if now.Before(g.pacer.Deadline()) {
		return nil
	}
	g.pacer.Advance(now)
	select {
	case next, ok := <-g.frames:
		if !ok {
			return errors.New("QR producer stopped")
		}
		if next.Err != nil {
			return next.Err
		}
		g.current.Dispose()
		g.current = ebiten.NewImageFromImage(next.Raster)
		g.redraw = true
		g.stats.displayed.Add(1)
	default:
		g.stats.missed.Add(1)
	}
	return nil
}

func (g *displayGame) Draw(screen *ebiten.Image) {
	// Retain the ready screen or QR raster until its contents change.
	if !g.redraw {
		return
	}
	g.redraw = false
	if !g.started {
		screen.Fill(color.RGBA{R: 16, G: 36, B: 62, A: 255})
		centerDebugText(screen, "DUD optical transfer sender ready", g.width/2-42)
		centerDebugText(screen, "Aim the receiver camera at this window.", g.width/2-18)
		ebitenutil.DrawRect(
			screen,
			float64(g.startButton.Min.X),
			float64(g.startButton.Min.Y),
			float64(g.startButton.Dx()),
			float64(g.startButton.Dy()),
			color.RGBA{R: 21, G: 94, B: 239, A: 255},
		)
		centerDebugText(screen, "Start  [Space or Enter]", g.startButton.Min.Y+17)
		return
	}
	screen.Fill(color.White)
	screen.DrawImage(g.current, nil)
}

func centerDebugText(screen *ebiten.Image, value string, y int) {
	x := (screen.Bounds().Dx() - len(value)*6) / 2
	ebitenutil.DebugPrintAt(screen, value, x, y)
}

func (g *displayGame) Layout(_, _ int) (int, int) {
	return g.width, g.width
}

// Check validates geometry against the selected local monitor before input work.
func Check(options display.Options) error {
	if err := options.Validate(); err != nil {
		return err
	}
	width, height := ebiten.Monitor().Size()
	if options.Side()+32 > width || options.Side()+96 > height {
		return errors.New("optical raster does not fit the monitor")
	}
	return nil
}
