import * as Dialog from "@radix-ui/react-dialog";
import { Clock } from "lucide-react";

import { Button } from "../../components/ui/primitives";

/**
 * A modal rather than a page, so an operator mid-way through a form does not
 * lose their place when the warning fires.
 */
export function SessionExpiryDialog({
  open,
  msRemaining,
  onStay,
  onEnd,
}: {
  open: boolean;
  msRemaining: number;
  onStay: () => void;
  onEnd: () => void;
}) {
  const seconds = Math.max(0, Math.ceil(msRemaining / 1000));
  const minutes = Math.floor(seconds / 60);
  const label = minutes > 0 ? `${minutes}:${String(seconds % 60).padStart(2, "0")}` : `${seconds}s`;

  return (
    <Dialog.Root open={open}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-50 bg-black/75 backdrop-blur-[2px]" />
        <Dialog.Content
          onEscapeKeyDown={(event) => event.preventDefault()}
          onInteractOutside={(event) => event.preventDefault()}
          className="fixed top-1/2 left-1/2 z-50 w-[min(26rem,94vw)] -translate-x-1/2 -translate-y-1/2 rounded-panel border border-state-warn/50 bg-charcoal-panel p-6 shadow-raised"
        >
          <div className="flex items-start gap-3.5">
            <span className="grid size-10 shrink-0 place-items-center rounded-control border border-state-warn/40 bg-state-warn/10 text-state-warn">
              <Clock className="size-5" strokeWidth={1.75} aria-hidden="true" />
            </span>
            <div className="min-w-0">
              <Dialog.Title className="text-[17px] font-semibold text-cream-bright">Still there?</Dialog.Title>
              <Dialog.Description className="mt-1.5 text-[13.5px] leading-relaxed text-sand-muted">
                Your administrative session ends in{" "}
                <span className="font-mono tabular-nums text-state-warn">{label}</span>. You will return to the workspace
                chooser — your investigation session stays open.
              </Dialog.Description>
            </div>
          </div>

          <div className="mt-6 flex gap-2">
            <Button variant="ghost" size="sm" onClick={onEnd} className="flex-1">
              End now
            </Button>
            <Button variant="primary" size="sm" onClick={onStay} className="flex-1" autoFocus>
              Stay signed in
            </Button>
          </div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
