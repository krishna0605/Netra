import { fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it } from "vitest";
import { PublicHomePage, PublicUpdatesPage } from "./PublicSite";

function renderHome() {
  return render(<MemoryRouter><PublicHomePage /></MemoryRouter>);
}

describe("public home interactions", () => {
  it("renders NETRA content and no pricing navigation", () => {
    const { container } = renderHome();
    expect(screen.getByRole("heading", { name: /see the traffic/i })).toBeInTheDocument();
    expect(screen.getByRole("navigation", { name: /public navigation/i })).toBeInTheDocument();
    expect(screen.queryByText(/^pricing$/i)).not.toBeInTheDocument();
    expect(screen.queryByRole("link", { name: /^blog$/i })).not.toBeInTheDocument();
    expect(container.querySelector(".overview-section .section-label > span")).not.toBeInTheDocument();
    expect(container.querySelector(".capabilities-section .section-label > span")).toHaveTextContent("01");
  });

  it("expands an operating layer and FAQ answer", () => {
    renderHome();
    const analysis = screen.getByRole("button", { name: /analysis layer/i });
    fireEvent.click(analysis);
    expect(analysis).toHaveAttribute("aria-expanded", "true");
    expect(screen.getByText(/decode protocols, reconstruct sessions/i)).toBeInTheDocument();

    const pcapFaq = screen.getByRole("button", { name: /can netra analyze a real packet capture/i });
    fireEvent.click(pcapFaq);
    expect(screen.getByText(/accepts PCAP evidence and produces packet/i)).toBeInTheDocument();
  });

  it("keeps the third-party player unloaded until configured and requested", () => {
    const { container } = renderHome();
    expect(screen.queryByTitle(/cybersecurity overview/i)).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: /video url is not configured/i })).toBeDisabled();
    expect(container.querySelector(".video-note")).not.toBeInTheDocument();
  });

  it("provides working footer navigation without removed destinations", () => {
    const { container } = renderHome();
    const footer = container.querySelector(".public-footer");
    expect(footer).not.toBeNull();
    expect(footer?.querySelector('a[href="#public-top"]')).toHaveTextContent(/back to top/i);
    expect(footer?.querySelector('a[href="/"]')).toHaveTextContent(/homepage/i);
    expect(footer?.querySelector('a[href="/about"]')).toHaveTextContent(/about/i);
    expect(footer?.querySelector('a[href="/updates"]')).toHaveTextContent(/updates/i);
    expect(footer?.querySelector('a[href="https://github.com/krishna0605/Netra"]')).toHaveTextContent(/github/i);
    expect(footer).not.toHaveTextContent(/youtube|community|contact netra/i);
    expect(footer?.querySelector('a[href="/contact"]')).not.toBeInTheDocument();
  });

  it("opens and closes mobile navigation", () => {
    const { container } = renderHome();
    const trigger = screen.getByLabelText(/toggle navigation/i);
    fireEvent.click(trigger);
    expect(trigger).toHaveAttribute("aria-expanded", "true");
    expect(container.querySelector(".mobile-public-nav")).toBeInTheDocument();
    fireEvent.click(trigger);
    expect(trigger).toHaveAttribute("aria-expanded", "false");
  });
});

describe("public updates interactions", () => {
  it("renders the India threat cards and expands guidance", () => {
    render(<MemoryRouter><PublicUpdatesPage /></MemoryRouter>);
    expect(screen.getAllByRole("article")).toHaveLength(6);
    expect(screen.getByText("22.68L")).toBeInTheDocument();
    expect(screen.getAllByText("1930", { selector: ".monitor-metrics strong" })).toHaveLength(2);
    expect(screen.getByRole("heading", { name: /how to register a cybercrime complaint/i })).toBeInTheDocument();
    const detail = screen.getByRole("button", { name: /highest public-facing risk/i });
    fireEvent.click(detail);
    expect(detail).toHaveAttribute("aria-expanded", "true");
    expect(screen.getByText(/financial fraud driven by impersonation/i)).toBeInTheDocument();
  });
});
