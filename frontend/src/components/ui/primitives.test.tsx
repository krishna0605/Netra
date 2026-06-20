import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { Button, Dialog, DialogContent, DialogTitle, DialogTrigger } from "./primitives";

describe("industrial UI primitives", () => {
  it("preserves accessible button semantics", () => {
    render(<Button>Generate report</Button>);
    expect(screen.getByRole("button", { name: "Generate report" })).toBeEnabled();
  });

  it("opens and closes an accessible dialog", () => {
    render(
      <Dialog>
        <DialogTrigger asChild><Button>Open evidence</Button></DialogTrigger>
        <DialogContent aria-describedby={undefined}><DialogTitle>Evidence detail</DialogTitle></DialogContent>
      </Dialog>,
    );
    fireEvent.click(screen.getByRole("button", { name: "Open evidence" }));
    expect(screen.getByRole("dialog")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /close/i }));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });
});
