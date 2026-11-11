// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

import type {
  FrameDisposition,
  PipelineCompletion,
  PipelineProgress,
} from './pipeline.js';

export const MAX_FOUNTAIN_PENDING_FRAMES = 32;
// Four in-flight QR images can each return four symbols after capture pauses.
export const FOUNTAIN_CAPTURE_HEADROOM = 16;
// Version 40 L's byte-segment capacity also admits malformed optical frames.
export const MAX_FOUNTAIN_FRAME_BYTES = 2953;

export interface FountainRequest {
  id: number;
  receivedAt: number;
  frame: ArrayBuffer;
}

export interface FountainIssue {
  type: 'session' | 'unsupported' | 'rejected' | 'fatal';
  value: string;
}

export type FountainResponse =
  | {
      type: 'processed';
      id: number;
      disposition?: FrameDisposition;
      progress?: PipelineProgress;
      issue?: FountainIssue;
      processingMilliseconds: number;
    }
  | {
      type: 'complete';
      completion: Omit<PipelineCompletion, 'capsule'>;
      capsule: ArrayBuffer;
    }
  | {
      type: 'failed';
      message: string;
    };
