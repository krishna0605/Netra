import { Slot } from "@radix-ui/react-slot";
import { cva, type VariantProps } from "class-variance-authority";
import type { ComponentProps, ReactNode } from "react";

import { cn } from "../../lib/utils";

/* ---------------------------------------------------------------------------
   Button
   --------------------------------------------------------------------------- */
const buttonVariants = cva(
  "inline-flex items-center justify-center gap-2 rounded-control font-medium whitespace-nowrap transition-colors disabled:pointer-events-none disabled:opacity-40",
  {
    variants: {
      variant: {
        primary: "bg-signal text-charcoal-deep hover:bg-signal-dark",
        outline: "border border-control-edge text-cream-primary hover:border-signal/70 hover:text-signal",
        ghost: "text-sand-muted hover:bg-cream-primary/6 hover:text-cream-bright",
        danger: "border border-state-crit/70 text-state-crit hover:bg-state-crit hover:text-charcoal-deep",
      },
      size: {
        sm: "h-8 px-3 text-[13px]",
        md: "h-9 px-4 text-sm",
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
   Tag — bordered pill. Reserved for *categorical* things: roles, permission
   keys, capability states. State (active, denied, MFA) uses <Status/> below,
   because five bordered pills in one table row is noise.
   --------------------------------------------------------------------------- */
const tagVariants = cva(
  "inline-flex items-center gap-1 rounded-chip border px-1.5 py-0.5 text-[11px] leading-4 font-medium whitespace-nowrap",
  {
    variants: {
      tone: {
        neutral: "border-hairline-strong text-sand-muted",
        accent: "border-signal/50 bg-signal/10 text-signal",
        ok: "border-state-ok/50 bg-state-ok/10 text-state-ok",
        warn: "border-state-warn/50 bg-state-warn/10 text-state-warn",
        crit: "border-state-crit/50 bg-state-crit/10 text-state-crit",
        info: "border-state-info/50 bg-state-info/10 text-state-info",
      },
      mono: { true: "font-mono text-[10.5px] tracking-[0.02em]", false: "" },
    },
    defaultVariants: { tone: "neutral", mono: false },
  },
);

export function Tag({ className, tone, mono, ...props }: ComponentProps<"span"> & VariantProps<typeof tagVariants>) {
  return <span className={cn(tagVariants({ tone, mono }), className)} {...props} />;
}

/* ---------------------------------------------------------------------------
   Status — dot plus word. Quieter than a pill and still readable without
   colour, because the word carries the meaning on its own.
   --------------------------------------------------------------------------- */
const DOT: Record<string, string> = {
  ok: "bg-state-ok",
  warn: "bg-state-warn",
  crit: "bg-state-crit",
  info: "bg-state-info",
  accent: "bg-signal",
  neutral: "bg-sand-muted/50",
};

const DOT_TEXT: Record<string, string> = {
  ok: "text-state-ok",
  warn: "text-state-warn",
  crit: "text-state-crit",
  info: "text-state-info",
  accent: "text-signal",
  neutral: "text-sand-muted",
};

export function Status({
  tone = "neutral",
  children,
  className,
}: {
  tone?: "ok" | "warn" | "crit" | "info" | "accent" | "neutral";
  children: ReactNode;
  className?: string;
}) {
  return (
    <span className={cn("inline-flex items-center gap-1.5 text-[13px] whitespace-nowrap", DOT_TEXT[tone], className)}>
      <span className={cn("size-1.5 shrink-0 rounded-full", DOT[tone])} aria-hidden="true" />
      {children}
    </span>
  );
}

/* ---------------------------------------------------------------------------
   Panel
   --------------------------------------------------------------------------- */
export function Panel({ className, ...props }: ComponentProps<"section">) {
  return (
    <section
      className={cn("rounded-panel border border-hairline bg-charcoal-panel shadow-panel", className)}
      {...props}
    />
  );
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
    <header className={cn("flex flex-wrap items-center justify-between gap-3 border-b border-hairline px-5 py-3.5", className)}>
      <div className="min-w-0">
        <h3 className="text-[15px] font-semibold text-cream-bright">{title}</h3>
        {hint ? <p className="mt-0.5 text-[13px] text-sand-muted/75">{hint}</p> : null}
      </div>
      {action}
    </header>
  );
}

/* ---------------------------------------------------------------------------
   Field — labelled value. Label in Geist, value in mono only when it is data
   you would cite: an id, an address, a hash, a timestamp.
   --------------------------------------------------------------------------- */
export function Field({ label, children, mono = true }: { label: string; children: ReactNode; mono?: boolean }) {
  return (
    <div className="grid grid-cols-[9rem_minmax(0,1fr)] items-baseline gap-3 py-2">
      <dt className="text-[13px] text-sand-muted/70">{label}</dt>
      <dd className={cn("min-w-0 text-[13px] break-words text-cream-primary", mono && "font-mono text-xs")}>{children}</dd>
    </div>
  );
}

/* ---------------------------------------------------------------------------
   Table
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
        "border-b border-hairline px-5 py-2.5 text-left text-[12px] font-medium whitespace-nowrap text-sand-muted/70",
        className,
      )}
      {...props}
    />
  );
}

export function Td({ className, ...props }: ComponentProps<"td">) {
  return <td className={cn("border-b border-hairline px-5 py-3 align-middle", className)} {...props} />;
}

/* ---------------------------------------------------------------------------
   Inputs
   --------------------------------------------------------------------------- */
export function Input({ className, ...props }: ComponentProps<"input">) {
  return (
    <input
      className={cn(
        "h-9 w-full rounded-control border border-control-edge bg-charcoal-deep px-3 text-sm text-cream-primary",
        "placeholder:text-sand-muted/70 focus:border-signal focus:outline-none",
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
        "w-full rounded-control border border-control-edge bg-charcoal-deep px-3 py-2 text-sm text-cream-primary",
        "placeholder:text-sand-muted/70 focus:border-signal focus:outline-none",
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
        "h-9 rounded-control border border-control-edge bg-charcoal-deep px-2.5 text-[13px] text-cream-primary",
        "focus:border-signal focus:outline-none",
        className,
      )}
      {...props}
    />
  );
}

/* ---------------------------------------------------------------------------
   Avatar — initials block. Anchors a name visually down a long list.
   --------------------------------------------------------------------------- */
export function Avatar({ initials, tone = "neutral", className }: { initials: string; tone?: "neutral" | "accent"; className?: string }) {
  return (
    <span
      aria-hidden="true"
      className={cn(
        "grid size-8 shrink-0 place-items-center rounded-control border font-mono text-[11px] font-semibold",
        tone === "accent" ? "border-signal/45 bg-signal/10 text-signal" : "border-hairline-strong bg-cream-primary/5 text-sand-muted",
        className,
      )}
    >
      {initials}
    </span>
  );
}

/* ---------------------------------------------------------------------------
   Empty state
   --------------------------------------------------------------------------- */
export function EmptyState({ title, hint }: { title: string; hint?: string }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 px-6 py-16 text-center">
      <img src="/brand/netra-logo-mark.svg" alt="" className="size-8 opacity-15" aria-hidden="true" />
      <p className="mt-1 text-sm text-cream-primary">{title}</p>
      {hint ? <p className="max-w-md text-[13px] text-sand-muted/70">{hint}</p> : null}
    </div>
  );
}
