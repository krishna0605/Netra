/* eslint-disable react-refresh/only-export-components */
import * as DialogPrimitive from "@radix-ui/react-dialog";
import * as ScrollAreaPrimitive from "@radix-ui/react-scroll-area";
import * as SelectPrimitive from "@radix-ui/react-select";
import * as SeparatorPrimitive from "@radix-ui/react-separator";
import * as SwitchPrimitive from "@radix-ui/react-switch";
import * as TabsPrimitive from "@radix-ui/react-tabs";
import * as TooltipPrimitive from "@radix-ui/react-tooltip";
import { Slot } from "@radix-ui/react-slot";
import { cva, type VariantProps } from "class-variance-authority";
import { Check, ChevronDown, X } from "lucide-react";
import type { ComponentPropsWithoutRef, ElementRef, ReactNode } from "react";
import { forwardRef } from "react";
import { cn } from "../../lib/utils";

const buttonVariants = cva(
  "inline-flex items-center justify-center gap-2 rounded-[2px] font-mono text-xs font-bold uppercase tracking-[0.04em] transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent)] focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50",
  {
    variants: {
      variant: {
        default: "bg-[var(--accent)] !text-[var(--charcoal-deep)] shadow-sm [clip-path:polygon(0_0,calc(100%_-_8px)_0,100%_8px,100%_100%,8px_100%,0_calc(100%_-_8px))] hover:brightness-110 hover:shadow-md",
        secondary: "border border-[var(--border-strong)] bg-[var(--cream-primary)] text-[var(--charcoal-deep)] hover:border-[var(--accent-line)] hover:bg-[var(--cream-bright)]",
        ghost: "text-[var(--text)] hover:bg-[var(--surface-muted)]",
        destructive: "border border-[var(--border-strong)] bg-[var(--text-strong)] text-[var(--bg)] hover:opacity-90",
        outline: "border border-[var(--border)] bg-transparent text-[var(--text)] hover:bg-[var(--surface-muted)]",
      },
      size: {
        default: "h-10 px-4 py-2",
        sm: "h-8 px-3 text-xs",
        lg: "h-11 px-5",
        icon: "size-9",
      },
    },
    defaultVariants: {
      variant: "default",
      size: "default",
    },
  },
);

export interface ButtonProps
  extends ComponentPropsWithoutRef<"button">,
    VariantProps<typeof buttonVariants> {
  asChild?: boolean;
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant, size, asChild = false, ...props }, ref) => {
    const Comp = asChild ? Slot : "button";
    return <Comp className={cn(buttonVariants({ variant, size, className }))} ref={ref} {...props} />;
  },
);
Button.displayName = "Button";

const badgeVariants = cva(
  "inline-flex items-center gap-1 rounded-[2px] border px-2 py-0.5 font-mono text-[0.65rem] font-semibold uppercase tracking-[0.04em]",
  {
    variants: {
      variant: {
        default: "border-[var(--accent-line)] bg-[var(--accent-soft)] text-[var(--accent)]",
        secondary: "border-[var(--border)] bg-[var(--surface-muted)] text-[var(--muted)]",
        success: "border-[var(--accent-line)] bg-[var(--accent-soft)] text-[var(--text)]",
        warning: "border-[var(--border-strong)] bg-[var(--surface-muted)] text-[var(--text)]",
        destructive: "border-[var(--border-strong)] bg-[var(--ink)] text-[var(--bg)]",
        teal: "border-[var(--accent-line)] bg-[var(--accent-soft)] text-[var(--accent)]",
      },
    },
    defaultVariants: {
      variant: "default",
    },
  },
);

export function Badge({
  className,
  variant,
  ...props
}: ComponentPropsWithoutRef<"span"> & VariantProps<typeof badgeVariants>) {
  return <span className={cn(badgeVariants({ variant, className }))} {...props} />;
}

export function Card({ className, ...props }: ComponentPropsWithoutRef<"div">) {
  return <div className={cn("rounded-[2px] surface-solid", className)} {...props} />;
}

export function CardHeader({ className, ...props }: ComponentPropsWithoutRef<"div">) {
  return <div className={cn("flex flex-col gap-1.5 p-5", className)} {...props} />;
}

export function CardTitle({ className, ...props }: ComponentPropsWithoutRef<"h3">) {
  return <h3 className={cn("text-base font-semibold text-[var(--text)]", className)} {...props} />;
}

export function CardDescription({ className, ...props }: ComponentPropsWithoutRef<"p">) {
  return <p className={cn("text-sm text-[var(--muted)]", className)} {...props} />;
}

export function CardContent({ className, ...props }: ComponentPropsWithoutRef<"div">) {
  return <div className={cn("p-5 pt-0", className)} {...props} />;
}

export function CardFooter({ className, ...props }: ComponentPropsWithoutRef<"div">) {
  return <div className={cn("flex items-center p-5 pt-0", className)} {...props} />;
}

export function Input({ className, ...props }: ComponentPropsWithoutRef<"input">) {
  return (
    <input
      className={cn(
        "h-10 w-full rounded-[2px] border border-[var(--border)] bg-[var(--surface-solid)] px-3 text-sm text-[var(--text)] outline-none transition placeholder:text-[var(--muted)] focus:border-[var(--accent)] focus:ring-2 focus:ring-[var(--accent-soft)]",
        className,
      )}
      {...props}
    />
  );
}

export function Textarea({ className, ...props }: ComponentPropsWithoutRef<"textarea">) {
  return (
    <textarea
      className={cn(
        "min-h-28 w-full rounded-[2px] border border-[var(--border)] bg-[var(--surface-solid)] px-3 py-2 text-sm text-[var(--text)] outline-none transition placeholder:text-[var(--muted)] focus:border-[var(--accent)] focus:ring-2 focus:ring-[var(--accent-soft)]",
        className,
      )}
      {...props}
    />
  );
}

export function Progress({ value = 0, className }: { value?: number; className?: string }) {
  return (
    <div className={cn("h-2 w-full overflow-hidden rounded-full bg-[var(--surface-muted)]", className)}>
      <div className="h-full rounded-full bg-[var(--accent)] transition-all duration-500" style={{ width: `${value}%` }} />
    </div>
  );
}

export function Skeleton({ className, ...props }: ComponentPropsWithoutRef<"div">) {
  return <div className={cn("animate-pulse rounded-md bg-[var(--surface-muted)]", className)} {...props} />;
}

export function Alert({ className, children }: { className?: string; children: ReactNode }) {
  return <div className={cn("rounded-[2px] border border-[var(--accent-line)] bg-[var(--accent-soft)] p-4 text-sm text-[var(--text)]", className)}>{children}</div>;
}

export const Separator = forwardRef<
  ElementRef<typeof SeparatorPrimitive.Root>,
  ComponentPropsWithoutRef<typeof SeparatorPrimitive.Root>
>(({ className, ...props }, ref) => (
  <SeparatorPrimitive.Root ref={ref} className={cn("h-px w-full bg-[var(--border)]", className)} {...props} />
));
Separator.displayName = "Separator";

export const Tabs = TabsPrimitive.Root;
export const TabsList = forwardRef<
  ElementRef<typeof TabsPrimitive.List>,
  ComponentPropsWithoutRef<typeof TabsPrimitive.List>
>(({ className, ...props }, ref) => (
  <TabsPrimitive.List ref={ref} className={cn("inline-flex rounded-[2px] border border-[var(--border)] bg-[var(--surface-muted)] p-1", className)} {...props} />
));
TabsList.displayName = "TabsList";

export const TabsTrigger = forwardRef<
  ElementRef<typeof TabsPrimitive.Trigger>,
  ComponentPropsWithoutRef<typeof TabsPrimitive.Trigger>
>(({ className, ...props }, ref) => (
  <TabsPrimitive.Trigger
    ref={ref}
    className={cn(
      "rounded-[1px] px-3 py-1.5 font-mono text-xs font-medium uppercase tracking-[0.04em] text-[var(--muted)] transition data-[state=active]:bg-[var(--cream-primary)] data-[state=active]:text-[var(--charcoal-deep)] data-[state=active]:shadow-sm",
      className,
    )}
    {...props}
  />
));
TabsTrigger.displayName = "TabsTrigger";
export const TabsContent = TabsPrimitive.Content;

export const Dialog = DialogPrimitive.Root;
export const DialogTrigger = DialogPrimitive.Trigger;
export const DialogTitle = DialogPrimitive.Title;
export const DialogClose = DialogPrimitive.Close;
export const DialogContent = forwardRef<
  ElementRef<typeof DialogPrimitive.Content>,
  ComponentPropsWithoutRef<typeof DialogPrimitive.Content>
>(({ className, children, ...props }, ref) => (
  <DialogPrimitive.Portal>
    <DialogPrimitive.Overlay className="fixed inset-0 z-50 bg-black/45 backdrop-blur-sm" />
    <DialogPrimitive.Content
      ref={ref}
      className={cn(
        "fixed left-1/2 top-1/2 z-50 w-[min(92vw,36rem)] -translate-x-1/2 -translate-y-1/2 rounded-[2px] border border-[var(--border)] bg-[var(--surface-solid)] p-6 text-[var(--text)] shadow-xl [clip-path:polygon(0_12px,12px_0,100%_0,100%_calc(100%_-_12px),calc(100%_-_12px)_100%,0_100%)]",
        className,
      )}
      {...props}
    >
      {children}
      <DialogPrimitive.Close aria-label="Close dialog" className="absolute right-4 top-4 rounded-md p-1 text-[var(--muted)] hover:bg-[var(--surface-muted)]">
        <X className="size-4" />
      </DialogPrimitive.Close>
    </DialogPrimitive.Content>
  </DialogPrimitive.Portal>
));
DialogContent.displayName = "DialogContent";

export const Sheet = DialogPrimitive.Root;
export const SheetTrigger = DialogPrimitive.Trigger;
export const SheetTitle = DialogPrimitive.Title;
export const SheetContent = forwardRef<
  ElementRef<typeof DialogPrimitive.Content>,
  ComponentPropsWithoutRef<typeof DialogPrimitive.Content>
>(({ className, children, ...props }, ref) => (
  <DialogPrimitive.Portal>
    <DialogPrimitive.Overlay className="fixed inset-0 z-50 bg-black/35 backdrop-blur-sm" />
    <DialogPrimitive.Content
      ref={ref}
      className={cn(
        "fixed right-0 top-0 z-50 h-full w-[min(92vw,28rem)] overflow-y-auto border-l border-[var(--border)] bg-[var(--surface-solid)] p-6 text-[var(--text)] shadow-xl",
        className,
      )}
      {...props}
    >
      {children}
      <DialogPrimitive.Close aria-label="Close sheet" className="absolute right-4 top-4 rounded-md p-1 text-[var(--muted)] hover:bg-[var(--surface-muted)]">
        <X className="size-4" />
      </DialogPrimitive.Close>
    </DialogPrimitive.Content>
  </DialogPrimitive.Portal>
));
SheetContent.displayName = "SheetContent";

export const Select = SelectPrimitive.Root;
export const SelectTrigger = forwardRef<
  ElementRef<typeof SelectPrimitive.Trigger>,
  ComponentPropsWithoutRef<typeof SelectPrimitive.Trigger>
>(({ className, children, ...props }, ref) => (
  <SelectPrimitive.Trigger
    ref={ref}
    className={cn(
      "flex h-10 min-w-36 items-center justify-between gap-2 rounded-[2px] border border-[var(--border)] bg-[var(--surface-solid)] px-3 font-mono text-xs text-[var(--text)] outline-none focus:ring-2 focus:ring-[var(--accent-soft)]",
      className,
    )}
    {...props}
  >
    {children}
    <SelectPrimitive.Icon>
      <ChevronDown className="size-4 opacity-60" />
    </SelectPrimitive.Icon>
  </SelectPrimitive.Trigger>
));
SelectTrigger.displayName = "SelectTrigger";
export const SelectValue = SelectPrimitive.Value;
export const SelectContent = forwardRef<
  ElementRef<typeof SelectPrimitive.Content>,
  ComponentPropsWithoutRef<typeof SelectPrimitive.Content>
>(({ className, children, ...props }, ref) => (
  <SelectPrimitive.Portal>
    <SelectPrimitive.Content ref={ref} className={cn("z-50 overflow-hidden rounded-md border border-[var(--border)] bg-[var(--surface-solid)] text-[var(--text)] shadow-lg", className)} {...props}>
      <SelectPrimitive.Viewport className="p-1">{children}</SelectPrimitive.Viewport>
    </SelectPrimitive.Content>
  </SelectPrimitive.Portal>
));
SelectContent.displayName = "SelectContent";
export const SelectItem = forwardRef<
  ElementRef<typeof SelectPrimitive.Item>,
  ComponentPropsWithoutRef<typeof SelectPrimitive.Item>
>(({ className, children, ...props }, ref) => (
  <SelectPrimitive.Item
    ref={ref}
    className={cn("relative flex cursor-pointer select-none items-center rounded-sm px-8 py-2 text-sm outline-none hover:bg-[var(--surface-muted)]", className)}
    {...props}
  >
    <SelectPrimitive.ItemIndicator className="absolute left-2">
      <Check className="size-4" />
    </SelectPrimitive.ItemIndicator>
    <SelectPrimitive.ItemText>{children}</SelectPrimitive.ItemText>
  </SelectPrimitive.Item>
));
SelectItem.displayName = "SelectItem";

export const Switch = forwardRef<
  ElementRef<typeof SwitchPrimitive.Root>,
  ComponentPropsWithoutRef<typeof SwitchPrimitive.Root>
>(({ className, ...props }, ref) => (
  <SwitchPrimitive.Root
    ref={ref}
    className={cn("relative h-6 w-11 rounded-full bg-[var(--surface-muted)] ring-1 ring-[var(--border)] transition data-[state=checked]:bg-[var(--accent)]", className)}
    {...props}
  >
    <SwitchPrimitive.Thumb className="block size-5 translate-x-0.5 rounded-full bg-[var(--text-strong)] shadow transition data-[state=checked]:translate-x-5" />
  </SwitchPrimitive.Root>
));
Switch.displayName = "Switch";

export const TooltipProvider = TooltipPrimitive.Provider;
export const Tooltip = TooltipPrimitive.Root;
export const TooltipTrigger = TooltipPrimitive.Trigger;
export const TooltipContent = forwardRef<
  ElementRef<typeof TooltipPrimitive.Content>,
  ComponentPropsWithoutRef<typeof TooltipPrimitive.Content>
>(({ className, ...props }, ref) => (
  <TooltipPrimitive.Content ref={ref} className={cn("z-50 rounded-md bg-[var(--text-strong)] px-2 py-1 text-xs text-[var(--bg)]", className)} {...props} />
));
TooltipContent.displayName = "TooltipContent";

export const ScrollArea = forwardRef<
  ElementRef<typeof ScrollAreaPrimitive.Root>,
  ComponentPropsWithoutRef<typeof ScrollAreaPrimitive.Root>
>(({ className, children, ...props }, ref) => (
  <ScrollAreaPrimitive.Root ref={ref} className={cn("overflow-hidden", className)} {...props}>
    <ScrollAreaPrimitive.Viewport className="size-full">{children}</ScrollAreaPrimitive.Viewport>
    <ScrollAreaPrimitive.Scrollbar className="flex touch-none select-none bg-[var(--surface-muted)] p-0.5" orientation="vertical">
      <ScrollAreaPrimitive.Thumb className="relative flex-1 rounded-full bg-[var(--border-strong)]" />
    </ScrollAreaPrimitive.Scrollbar>
  </ScrollAreaPrimitive.Root>
));
ScrollArea.displayName = "ScrollArea";
