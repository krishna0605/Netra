import { Slot } from "@radix-ui/react-slot";
import { cva, type VariantProps } from "class-variance-authority";
import type { ComponentProps, ReactNode } from "react";

import { cn } from "../../lib/utils";

/* ---------------------------------------------------------------------------
   Button
   --------------------------------------------------------------------------- */
const buttonVariants = cva(
  "inline-flex items-center justify-center gap-2 whitespace-nowrap rounded-sm font-medium transition-colors disabled:pointer-events-none disabled:opacity-45",
  {
    variants: {
      variant: {
        primary: "bg-signal text-charcoal-deep hover:bg-signal-dark",
        outline: "border border-hairline-strong text-cream-primary hover:border-signal hover:text-signal",
        ghost: "text-sand-muted hover:bg-cream-primary/6 hover:text-cream-bright",
        danger: "border border-state-crit text-state-crit hover:bg-state-crit hover:text-charcoal-deep",
      },
      size: {
        sm: "h-7 px-2.5 text-xs",
        md: "h-9 px-3.5 text-sm",
      },
    },
    defaultVariants: { variant: "outline", size: "md" },
  },
);

export function Button({
  className,
  variant,
  size,
  asChild = false,
  ...props
}: ComponentProps<"button"> & VariantProps<typeof buttonVariants> & { asChild?: boolean }) {
  const Component = asChild ? Slot : "button";
  return <Component className={cn(buttonVariants({ variant, size }), className)} {...props} />;
}

/* ---------------------------------------------------------------------------
   Badge — the single most-used element in this console. State is encoded in
   colour *and* in the word, never colour alone.
   --------------------------------------------------------------------------- */
const badgeVariants = cva(
  "inline-flex items-center gap-1 rounded-xs border px-1.5 py-0.5 font-mono text-[10px] leading-4 tracking-[0.06em] uppercase whitespace-nowrap",
  {
    variants: {
      tone: {
        neutral: "border-hairline-strong text-sand-muted",
        accent: "border-signal/60 bg-signal/12 text-signal",
        ok: "border-state-ok/60 bg-state-ok/12 text-state-ok",
        warn: "border-state-warn/60 bg-state-warn/12 text-state-warn",
        crit: "border-state-crit/60 bg-state-crit/12 text-state-crit",
        info: "border-state-info/60 bg-state-info/12 text-state-info",
      },
    },
    defaultVariants: { tone: "neutral" },
  },
);

export function Badge({ className, tone, ...props }: ComponentProps<"span"> & VariantProps<typeof badgeVariants>) {
  return <span className={cn(badgeVariants({ tone }), className)} {...props} />;
}

/* ---------------------------------------------------------------------------
   Panel — the standard content container
   --------------------------------------------------------------------------- */
export function Panel({ className, ...props }: ComponentProps<"section">) {
  return <section className={cn("border border-hairline bg-charcoal-panel/94", className)} {...props} />;
}

export function PanelHeader({
  title,
  hint,
  action,
  className,
}: {
  title: string;
  hint?: ReactNode;
  action?: ReactNode;
  className?: string;
}) {
  return (
    <header className={cn("flex flex-wrap items-center justify-between gap-3 border-b border-hairline px-4 py-2.5", className)}>
      <div className="min-w-0">
        <h3 className="font-mono text-[11px] tracking-[0.13em] text-sand-muted uppercase">{title}</h3>
        {hint ? <p className="mt-0.5 text-xs text-sand-muted/70">{hint}</p> : null}
      </div>
      {action}
    </header>
  );
}

/* ---------------------------------------------------------------------------
   Field — read-only labelled value, used across detail views
   --------------------------------------------------------------------------- */
export function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="grid grid-cols-[8.5rem_minmax(0,1fr)] items-baseline gap-3 py-1.5">
      <dt className="font-mono text-[10px] tracking-[0.1em] text-sand-muted/70 uppercase">{label}</dt>
      <dd className="min-w-0 font-mono text-xs break-words text-cream-primary">{children}</dd>
    </div>
  );
}

/* ---------------------------------------------------------------------------
   Table shell — every list in this console shares these rules so a row means
   the same thing everywhere.
   --------------------------------------------------------------------------- */
export function TableWrap({ className, ...props }: ComponentProps<"div">) {
  return <div className={cn("w-full overflow-x-auto", className)} {...props} />;
}

export function Table({ className, ...props }: ComponentProps<"table">) {
  return <table className={cn("w-full min-w-[46rem] border-collapse text-sm", className)} {...props} />;
}

export function Th({ className, ...props }: ComponentProps<"th">) {
  return (
    <th
      className={cn(
        "border-b border-hairline-strong bg-charcoal-deep/60 px-4 py-2 text-left font-mono text-[10px] tracking-[0.1em] whitespace-nowrap text-sand-muted/80 uppercase",
        className,
      )}
      {...props}
    />
  );
}

export function Td({ className, ...props }: ComponentProps<"td">) {
  return <td className={cn("border-b border-hairline px-4 py-2.5 align-middle", className)} {...props} />;
}

/* ---------------------------------------------------------------------------
   Inputs
   --------------------------------------------------------------------------- */
export function Input({ className, ...props }: ComponentProps<"input">) {
  return (
    <input
      className={cn(
        "h-9 w-full rounded-sm border border-hairline bg-charcoal-deep px-3 text-sm text-cream-primary",
        "placeholder:text-sand-muted/50 focus:border-signal focus:outline-none",
        className,
      )}
      {...props}
    />
  );
}

export function Textarea({ className, ...props }: ComponentProps<"textarea">) {
  return (
    <textarea
      className={cn(
        "w-full rounded-sm border border-hairline bg-charcoal-deep px-3 py-2 text-sm text-cream-primary",
        "placeholder:text-sand-muted/50 focus:border-signal focus:outline-none",
        className,
      )}
      {...props}
    />
  );
}

export function NativeSelect({ className, ...props }: ComponentProps<"select">) {
  return (
    <select
      className={cn(
        "h-9 rounded-sm border border-hairline bg-charcoal-deep px-2.5 text-sm text-cream-primary",
        "focus:border-signal focus:outline-none",
        className,
      )}
      {...props}
    />
  );
}

/* ---------------------------------------------------------------------------
   Empty state
   --------------------------------------------------------------------------- */
export function EmptyState({ title, hint }: { title: string; hint?: string }) {
  return (
    <div className="flex flex-col items-center justify-center gap-1.5 px-6 py-14 text-center">
      <p className="font-mono text-sm text-cream-primary">{title}</p>
      {hint ? <p className="max-w-md text-xs text-sand-muted/70">{hint}</p> : null}
    </div>
  );
}
