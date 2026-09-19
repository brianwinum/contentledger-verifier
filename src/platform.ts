// SPDX-License-Identifier: GPL-2.0-or-later
import type { CheckResult, Expectations, SelectedPackage } from './model';
import type { BrowserBuildInfo } from './browser-build-info';

export type PackageInput = string | File;
export interface DropCallbacks {
  select(input: PackageInput): void;
  error(message: string): void;
  dragging(active: boolean): void;
}
export interface CheckerPlatform {
  kind: 'browser';
  available: boolean;
  readonly buildInfo?: BrowserBuildInfo | null;
  selectionError: string;
  cancellationMessage: string;
  select(input?: PackageInput): Promise<SelectedPackage | null>;
  verify(packageId: string, expectations: Expectations): Promise<unknown>;
  cancel(): Promise<void>;
  save(result: CheckResult): Promise<'saved' | 'download_requested' | 'cancelled'>;
  listenForDrops(callbacks: DropCallbacks): Promise<void>;
}
