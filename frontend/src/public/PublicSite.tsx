import { AnimatePresence, motion, useReducedMotion } from "framer-motion";
import {
  Activity,
  ArrowRight,
  Check,
  ChevronDown,
  Database,
  FileCheck2,
  Fingerprint,
  LockKeyhole,
  Menu,
  Network,
  Play,
  Radar,
  X,
} from "lucide-react";
import { useEffect, useMemo, useRef, useState, type FormEvent, type ReactNode } from "react";
import { Link, NavLink, useLocation } from "react-router-dom";
import { Button, Input, Textarea } from "../components/ui/primitives";
import { capabilityRows, faqRows, integrationRows, publicUpdates } from "./content";
import "./public-site.css";

type PublicPageProps = { languageControl?: ReactNode };

// Use "instant" so the page jumps to the top rather than smooth-scrolling
// through the newly navigated page (html { scroll-behavior: smooth } is global).
const resetScroll = () => window.scrollTo({ top: 0, left: 0, behavior: "instant" });
const resetScrollAfterNavigation = () => window.setTimeout(resetScroll, 0);

const workflow = [
  ["Register evidence", "Record case, source, investigator, priority, and SHA-256 identity."],
  ["Parse traffic", "Extract packet, flow, protocol, and encrypted metadata records."],
  ["Correlate signals", "Join rule matches, anomalies, sessions, and destinations."],
  ["Build the case", "Preserve notes, custody actions, linked evidence, and review history."],
  ["Generate report", "Export a clear account of observations, limitations, and next steps."],
] as const;

const featureRows = [
  [Fingerprint, "Evidence integrity", "Keep hashes, timestamps, source context, custody, and investigator actions close to every finding."],
  [LockKeyhole, "Encrypted metadata", "Study SNI, JA3, certificates, packet sizes, timing, and reputation without decrypting protected content."],
  [Radar, "Explainable anomaly review", "See model mode, contributing signals, baseline deviation, fallback status, and limitations."],
  [Network, "Attack-path reconstruction", "Move from a host or alert to connected sessions, destinations, protocols, and evidence."],
  [FileCheck2, "Case-ready reporting", "Generate authenticated reports and exports in English, Hindi, and Gujarati."],
  [Activity, "Operational collection", "Manage sensors, capture schedules, retention, integrations, and technical readiness."],
] as const;

const homeSections = ["Capabilities", "Numbers", "Features", "Integrations", "Investigation", "FAQ"] as const;

function useDispatchReveal() {
  const reduceMotion = useReducedMotion();
  return (delay = 0) => reduceMotion ? { initial: false as const } : {
    initial: { opacity: .001, y: 24 },
    animate: { opacity: 1, y: 0 },
    transition: { type: "spring" as const, duration: 1, bounce: .2, delay },
  };
}

function useSectionRail(prefix: string, count: number) {
  const [activeSection, setActiveSection] = useState(0);
  const [sectionProgress, setSectionProgress] = useState(0);
  const activeSectionRef = useRef(0);

  useEffect(() => {
    const sections = Array.from({ length: count }, (_, index) => document.getElementById(`${prefix}-${index + 1}`)).filter((section): section is HTMLElement => Boolean(section));
    if (!sections.length) return;

    const activate = (index: number) => {
      activeSectionRef.current = index;
      setActiveSection(index);
    };
    const observer = new IntersectionObserver((entries) => {
      const visible = entries.filter((entry) => entry.isIntersecting).sort((a, b) => b.intersectionRatio - a.intersectionRatio)[0];
      if (visible) activate(sections.indexOf(visible.target as HTMLElement));
    }, { rootMargin: "-12% 0px -58% 0px", threshold: [0, .1, .25, .5, .75] });
    sections.forEach((section) => observer.observe(section));

    let scheduled = false;
    const updateProgress = () => {
      scheduled = false;
      const marker = window.innerHeight * .32;
      let index = sections.findIndex((section) => {
        const rect = section.getBoundingClientRect();
        return rect.top <= marker && rect.bottom > marker;
      });
      if (index < 0) index = activeSectionRef.current;
      const rect = sections[index].getBoundingClientRect();
      const progress = Math.max(0, Math.min(1, (marker - rect.top) / Math.max(rect.height, 1)));
      if (index !== activeSectionRef.current) activate(index);
      setSectionProgress(progress);
    };
    const onScroll = () => {
      if (scheduled) return;
      scheduled = true;
      window.requestAnimationFrame(updateProgress);
    };
    window.addEventListener("scroll", onScroll, { passive: true });
    updateProgress();
    return () => {
      observer.disconnect();
      window.removeEventListener("scroll", onScroll);
    };
  }, [prefix, count]);

  return { activeSection, sectionProgress };
}

function BrandLockup() {
  return <img className="netra-brand-lockup" src="/brand/netra-wordmark-full.svg" alt="" aria-hidden="true" />;
}

function PublicHeader({ languageControl }: PublicPageProps) {
  const [open, setOpen] = useState(false);
  const links = [["Home", "/"], ["About", "/about"], ["Updates", "/updates"]] as const;
  return (
    <header className="public-header">
      <Link to="/" className="brand-block" aria-label="NETRA home">
        <BrandLockup />
      </Link>
      <nav className="desktop-public-nav" aria-label="Public navigation">
        {links.map(([label, href]) => <NavLink key={href} to={href}>{label}</NavLink>)}
      </nav>
      <div className="header-actions">
        {languageControl}
        <Button asChild className="clip-button header-cta"><Link to="/login" state={{ from: "/app/upload" }}>Open console</Link></Button>
        <button className="mobile-menu-button" type="button" aria-label="Toggle navigation" aria-expanded={open} onClick={() => setOpen((value) => !value)}>
          {open ? <X /> : <Menu />}
        </button>
      </div>
      <AnimatePresence>
        {open && (
          <motion.nav className="mobile-public-nav" initial={{ opacity: 0, y: -12 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -12 }}>
            {links.map(([label, href]) => <NavLink key={href} to={href} onClick={() => setOpen(false)}>{label}</NavLink>)}
            <Link to="/contact" onClick={() => setOpen(false)}>Contact</Link>
          </motion.nav>
        )}
      </AnimatePresence>
    </header>
  );
}

function SectionLabel({ children, index }: { children: ReactNode; index?: string }) {
  return (
    <div className="section-label">
      {index && <span>{index}</span>}
      <strong>{children}</strong>
      <i />
    </div>
  );
}

function TextRoll({ children }: { children: string }) {
  return <span className="text-roll"><span>{children}</span><span aria-hidden="true">{children}</span></span>;
}

function LayerDiagram() {
  const reveal = useDispatchReveal();
  return (
    <motion.div className="layer-diagram" aria-label="Packet evidence processing layers" {...reveal(.3)}>
      <svg viewBox="0 0 620 800" role="img">
        <title>Packet evidence moving through capture, analysis, investigation, and reporting layers</title>
        <defs>
          <pattern id="dots" width="8" height="8" patternUnits="userSpaceOnUse"><circle cx="1" cy="1" r="1" fill="currentColor" opacity=".2" /></pattern>
          <linearGradient id="signal" x1="0" x2="0" y1="0" y2="1"><stop stopColor="#fa6c34" /><stop offset="1" stopColor="#e9e0d1" /></linearGradient>
        </defs>
        <rect width="620" height="800" fill="url(#dots)" />
        <path className="diagram-spine" d="M310 40V760" />
        <g className="diagram-layer layer-one"><path d="M175 128 310 52l135 76-135 76z" /><path d="M175 128v52l135 78 135-78v-52" /></g>
        <g className="diagram-layer layer-two"><path d="M105 332 310 218l205 114-205 116z" /><ellipse cx="310" cy="332" rx="104" ry="84" /></g>
        <g className="diagram-layer layer-three"><path d="M158 520 310 430l152 90-152 88z" /><path d="M158 520v62l152 88 152-88v-62" /></g>
        <g className="diagram-layer layer-four"><path d="M126 694 310 590l184 104-184 104z" /><path d="m220 690 90-50 90 50-90 52z" /></g>
        <g className="diagram-callouts">
          <path d="M310 128h210" /><circle cx="310" cy="128" r="5" /><text x="530" y="134">CAPTURE</text>
          <path d="M310 332h210" /><circle cx="310" cy="332" r="5" /><text x="530" y="338">ANALYZE</text>
          <path d="M310 520h210" /><circle cx="310" cy="520" r="5" /><text x="530" y="526">INVESTIGATE</text>
          <path d="M310 694h210" /><circle cx="310" cy="694" r="5" /><text x="530" y="700">REPORT</text>
        </g>
        <circle className="signal-dot" cx="310" cy="40" r="7" fill="url(#signal)" />
      </svg>
    </motion.div>
  );
}

function MosaicPoster() {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    if (navigator.userAgent.toLowerCase().includes("jsdom")) return;
    const context = canvas.getContext("2d");
    if (!context) return;
    const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    let frame = 0;
    let animationFrame = 0;

    const draw = () => {
      const width = canvas.clientWidth;
      const height = canvas.clientHeight;
      const ratio = Math.min(window.devicePixelRatio || 1, 2);
      if (canvas.width !== width * ratio || canvas.height !== height * ratio) {
        canvas.width = width * ratio;
        canvas.height = height * ratio;
      }
      context.setTransform(ratio, 0, 0, ratio, 0, 0);
      context.fillStyle = "#202020";
      context.fillRect(0, 0, width, height);

      const step = width < 700 ? 7 : 8;
      const phase = reducedMotion ? 0 : Math.sin(frame / 45) * 5;
      for (let y = 3; y < height; y += step) {
        for (let x = 3; x < width; x += step) {
          const nx = x / width;
          const ny = y / height;
          const rack = nx > .08 && nx < .34 && ny > .14 && ny < .86 && Math.sin(y * .19) > -.35;
          const analyst = ((nx - .67) ** 2) / .018 + ((ny - .48) ** 2) / .12 < 1;
          const consoleGlow = nx > .39 && nx < .63 && ny > .27 && ny < .68 && Math.sin((x + y + phase) * .035) > .2;
          const route = Math.abs(ny - (.78 - nx * .48 + Math.sin(nx * 12 + frame / 35) * .025)) < .012;
          const vignette = Math.max(0, 1 - Math.hypot(nx - .5, ny - .5) * 1.25);
          const active = rack || analyst || consoleGlow || route;
          const alpha = active ? .34 + vignette * .55 : .08 + vignette * .08;
          context.beginPath();
          context.fillStyle = route || (consoleGlow && (x + y) % 31 < 8)
            ? `rgba(255,112,56,${alpha})`
            : `rgba(240,231,218,${alpha})`;
          context.arc(x, y, active ? 1.55 : 1.05, 0, Math.PI * 2);
          context.fill();
        }
      }
      frame += 1;
      if (!reducedMotion) animationFrame = window.requestAnimationFrame(draw);
    };

    const observer = new ResizeObserver(draw);
    observer.observe(canvas);
    draw();
    return () => {
      observer.disconnect();
      window.cancelAnimationFrame(animationFrame);
    };
  }, []);

  return <canvas ref={canvasRef} className="mosaic-canvas" aria-hidden="true" />;
}

function CyberVideo() {
  const [playing, setPlaying] = useState(false);
  const rawUrl = String(import.meta.env.VITE_CYBER_VIDEO_URL ?? "").trim();
  const embedUrl = useMemo(() => {
    if (!rawUrl) return "";
    try {
      const url = new URL(rawUrl);
      if (url.hostname.includes("youtu.be")) return `https://www.youtube-nocookie.com/embed/${url.pathname.slice(1)}?autoplay=1&rel=0`;
      if (url.hostname.includes("youtube.com")) {
        const id = url.searchParams.get("v") ?? url.pathname.split("/").filter(Boolean).at(-1);
        return id ? `https://www.youtube-nocookie.com/embed/${id}?autoplay=1&rel=0` : "";
      }
      if (url.hostname.includes("vimeo.com")) {
        const id = url.pathname.split("/").filter(Boolean).at(-1);
        return id ? `https://player.vimeo.com/video/${id}?autoplay=1&dnt=1` : "";
      }
    } catch {
      return "";
    }
    return "";
  }, [rawUrl]);

  return (
    <section className="video-section" id="video">
      <div className="video-frame">
        {playing && embedUrl ? (
          <iframe src={embedUrl} title="NETRA cybersecurity overview" allow="autoplay; encrypted-media; picture-in-picture" allowFullScreen />
        ) : (
          <div className="video-poster">
            <MosaicPoster />
            <div className="poster-scan" />
            <div className="poster-terminal" aria-hidden="true">
              <span>CASE / NET-2026-0417</span>
              <strong>PACKET EVIDENCE</strong>
              <i />
              <p>HASH VERIFIED · 12 SIGNALS · 04 PATHS</p>
            </div>
            <button type="button" className="play-button" onClick={() => setPlaying(true)} disabled={!embedUrl} aria-label={embedUrl ? "Play NETRA cybersecurity video" : "Cybersecurity video URL is not configured"}>
              <Play fill="currentColor" />
              <TextRoll>{embedUrl ? "Play video" : "Video pending"}</TextRoll>
            </button>
          </div>
        )}
      </div>
    </section>
  );
}

function PublicFooter() {
  const githubUrl = String(import.meta.env.VITE_GITHUB_URL ?? "https://github.com/krishna0605/Netra").trim();
  const linkedinUrl = String(import.meta.env.VITE_LINKEDIN_URL ?? "").trim();
  return (
    <footer className="public-footer">
      <div className="footer-dark-frame">
        <aside className="footer-badges"><a href="#public-top">Back to top</a><span>SHA-256</span><span>CUSTODY</span><span>3 LANG</span></aside>
        <div className="footer-message">
          <SectionLabel>Ready for evidence</SectionLabel>
          <h2>Trace the signal.<br />Build the case.</h2>
          <p>Connect evidence, preserve context, and move from packet-level facts to an investigator-readable report.</p>
          <Button asChild className="clip-button cream-button"><Link to="/login" state={{ from: "/app/upload" }}><TextRoll>Start investigation</TextRoll></Link></Button>
        </div>
        <div className="footer-links">
          <div className="footer-arcs" aria-hidden="true"><svg viewBox="0 0 550 150" preserveAspectRatio="none">{[40, 95, 150, 205, 260, 315, 370].map((start, index) => <path key={start} d={`M${start} 150 Q${start + 100 + index * 6} ${-32 - index * 4} ${520 - index * 7} 150`} />)}</svg></div>
          <div><strong>Pages</strong><Link to="/" onClick={resetScrollAfterNavigation}>Homepage</Link><Link to="/about" onClick={resetScrollAfterNavigation}>About</Link><Link to="/updates" onClick={resetScrollAfterNavigation}>Updates</Link></div>
          <div><strong>Social</strong><a href={githubUrl} target="_blank" rel="noreferrer">GitHub</a>{linkedinUrl ? <a href={linkedinUrl} target="_blank" rel="noreferrer">LinkedIn</a> : <span>LinkedIn</span>}</div>
        </div>
      </div>
      <div className="footer-ticket">
        <div className="ticket-stub"><img className="ticket-symbol" src="/brand/netra-symbol.svg" alt="" aria-hidden="true" /></div>
        <div className="ticket-body"><div className="ticket-meta"><div><strong>ACTIVE</strong><span>Analysis status</span></div><div><strong>SHA-256</strong><span>Evidence identity</span></div><p>AI-assisted network forensics for evidence-aware cybercrime investigation.</p></div><img className="ticket-wordmark" src="/brand/netra-wordmark-full.svg" alt="NETRA — Network Evidence, Total Response, Assured" /></div>
      </div>
      <div className="footer-bottom"><span>NETRA · 2026</span><span><Link to="/terms">Terms</Link> · <Link to="/privacy">Privacy</Link> · Observe facts. Preserve context. Explain conclusions.</span></div>
    </footer>
  );
}

function PublicShell({ children, languageControl, className = "" }: PublicPageProps & { children: ReactNode; className?: string }) {
  const { pathname } = useLocation();
  // Reset to the top of the page whenever the route changes (e.g. Home / About / Updates nav).
  useEffect(() => {
    resetScroll();
  }, [pathname]);
  return <div id="public-top" className={`public-site ${className}`.trim()}><PublicHeader languageControl={languageControl} />{children}<PublicFooter /></div>;
}

export function PublicHomePage({ languageControl }: PublicPageProps) {
  const [activeLayer, setActiveLayer] = useState(0);
  const [openFaq, setOpenFaq] = useState(0);
  const { activeSection, sectionProgress } = useSectionRail("home", homeSections.length);
  const reveal = useDispatchReveal();

  return (
    <PublicShell languageControl={languageControl} className="home-public-site">
      <main>
        <section className="hero-section" id="hero">
          <aside className="hero-audience"><span>Built for</span><strong>Cybercrime teams</strong><div className="audience-symbol"><i /><i /><i /></div><div className="audience-symbol stacked"><i /><i /><i /></div></aside>
          <div className="hero-copy">
            <motion.div {...reveal(0)}><SectionLabel>Network evidence, structured for investigation</SectionLabel></motion.div>
            <motion.h1 {...reveal(.1)}>See the traffic.<br /><em>Build</em><br /><em>the case.</em></motion.h1>
            <motion.p {...reveal(.2)}>NETRA turns packet captures into timelines, protocol evidence, explainable threat signals, custody history, and multilingual forensic reports.</motion.p>
            <motion.div {...reveal(.3)}><Button asChild className="clip-button cream-button hero-button"><Link to="/login" state={{ from: "/app/upload" }}><TextRoll>Open investigation console</TextRoll></Link></Button></motion.div>
            <div className="layer-accordion">
              {[["Capture layer", "Register evidence, calculate identity, and preserve source context."], ["Analysis layer", "Decode protocols, reconstruct sessions, and compare behaviour."], ["Investigation layer", "Review alerts, anomalies, attack paths, notes, and custody."], ["Reporting layer", "Generate authenticated exports and multilingual case summaries."]].map(([title, body], index) => (
                <button type="button" key={title} className={activeLayer === index ? "active" : ""} onClick={() => setActiveLayer(index)} aria-expanded={activeLayer === index}>
                  <span>0{index + 1}</span><strong>{title}</strong><ChevronDown />
                  <AnimatePresence initial={false}>{activeLayer === index && <motion.p initial={{ height: 0, opacity: 0 }} animate={{ height: "auto", opacity: 1 }} exit={{ height: 0, opacity: 0 }}>{body}</motion.p>}</AnimatePresence>
                </button>
              ))}
            </div>
          </div>
          <LayerDiagram />
        </section>

        <CyberVideo />

        <section className="overview-section section-grid">
          <div><SectionLabel>Overview</SectionLabel><h2>One evidence chain from intake to report.</h2><p>Each stage keeps the active case and original evidence close, so investigators can move from a signal back to supporting traffic.</p></div>
          <div className="workflow-stack">
            {workflow.map(([title, body], index) => <motion.article key={title} initial={{ opacity: .35, x: 20 }} whileInView={{ opacity: 1, x: 0 }} viewport={{ once: true }}><span>0{index + 1}</span><div><strong>{title}</strong><p>{body}</p></div></motion.article>)}
          </div>
        </section>

        <div className="home-section-system">
          <aside className="section-rail" aria-label="Homepage sections">
            {homeSections.map((label, index) => <a key={label} href={`#home-${index + 1}`} className={activeSection === index ? "active" : ""} aria-current={activeSection === index ? "location" : undefined}><span>0{index + 1}</span>{label}<i style={{ transform: `scaleX(${activeSection === index ? sectionProgress : 0})` }} /></a>)}
          </aside>
          <div className="home-section-stack">
        <section className="capabilities-section cream-section ticket-panel" id="home-1">
          <SectionLabel index="01">Capabilities</SectionLabel>
          <div className="section-intro"><h2>Evidence operations,<br />connected end to end.</h2><p>Capture, decode, detect, explain, investigate, and report without separating findings from their case context.</p></div>
          <div className="capability-table">
            {capabilityRows.map((row) => <article key={row.number}><span>{row.number}</span><h3>{row.title}</h3><p>{row.body}</p></article>)}
          </div>
        </section>

        <section className="metrics-section cream-section ticket-panel" id="home-2">
          <SectionLabel index="02">Measured surface</SectionLabel>
          <div className="section-intro"><h2>Coverage grounded<br />in the working system.</h2><p>These figures describe implemented analysis surfaces, not invented customer outcomes.</p></div>
          <div className="metric-grid">
            <article><small>DETECTION FAMILIES</small><strong>12</strong><p>Rule definitions covering repeatable suspicious behaviour.</p></article>
            <article><small>DECODED PROTOCOLS</small><strong>08</strong><p>DNS, HTTP, TLS, FTP, SMTP, ICMP, TCP, and UDP.</p></article>
            <article><small>REPORT LANGUAGES</small><strong>03</strong><p>English, Hindi, and Gujarati investigation modes.</p></article>
            <article><small>EVIDENCE IDENTITY</small><strong>256</strong><p>SHA-256 digest recorded through the evidence workflow.</p></article>
          </div>
        </section>

        <section className="features-section section-grid ticket-panel" id="home-3">
          <div><SectionLabel index="03">Core systems</SectionLabel><h2>Designed for review, not black-box certainty.</h2></div>
          <div className="feature-list">
            {featureRows.map(([Icon, title, body], index) => <article key={title}><span>0{index + 1}</span><Icon /><div><h3>{title}</h3><p>{body}</p></div></article>)}
          </div>
        </section>

        <section className="integrations-section cream-section ticket-panel" id="home-4">
          <SectionLabel index="04">Operations</SectionLabel>
          <div className="section-intro"><h2>Connect evidence to the tools around the case.</h2><p>NETRA exposes operational paths without claiming integrations that the backend does not implement.</p></div>
          <div className="integration-grid">{integrationRows.map(([title, body]) => <article key={title}><Database /><h3>{title}</h3><p>{body}</p></article>)}</div>
        </section>

        <section className="scenario-section section-grid ticket-panel" id="home-5">
          <div><SectionLabel index="05">Investigation scenario</SectionLabel><h2>A suspicious workstation leaves more than one clue.</h2><p>A documented example replaces marketing testimonials with an inspectable evidence story.</p></div>
          <div className="scenario-path">
            {["Periodic DNS queries", "Long encoded labels", "Repeated TLS timing", "Linked destination risk", "Case timeline and report"].map((label, index) => <motion.div key={label} initial={{ opacity: .2 }} whileInView={{ opacity: 1 }} viewport={{ once: true }} transition={{ delay: index * .08 }}><span>0{index + 1}</span><i /><strong>{label}</strong><Check /></motion.div>)}
          </div>
        </section>

        <section className="faq-section section-grid ticket-panel" id="home-6">
          <div><SectionLabel index="06">FAQ</SectionLabel><h2>Important limits,<br />stated plainly.</h2><p>Still need technical detail? The repository documentation covers deployment, detection, forensics, and operational readiness.</p></div>
          <div className="faq-list">{faqRows.map((row, index) => <button type="button" key={row.question} onClick={() => setOpenFaq(openFaq === index ? -1 : index)} aria-expanded={openFaq === index}><span>0{index + 1}</span><strong>{row.question}</strong><ChevronDown />{openFaq === index && <motion.p initial={{ opacity: 0 }} animate={{ opacity: 1 }}>{row.answer}</motion.p>}</button>)}</div>
        </section>
          </div>
        </div>
      </main>
    </PublicShell>
  );
}

function InteriorHero({ label, title, body }: { label: string; title: string; body: string }) {
  const reveal = useDispatchReveal();
  return <section className="interior-hero"><motion.div {...reveal(0)}><SectionLabel>{label}</SectionLabel></motion.div><motion.h1 {...reveal(.1)}>{title}</motion.h1><motion.p {...reveal(.2)}>{body}</motion.p></section>;
}

const aboutSections = ["Values", "Disciplines", "Contribute", "Scenario"] as const;

export function PublicAboutPage(props: PublicPageProps) {
  const reveal = useDispatchReveal();
  const { activeSection, sectionProgress } = useSectionRail("about", aboutSections.length);
  const values = [
    ["Evidence before inference", "Every alert and anomaly should lead back to observable traffic and case context."],
    ["Explain the limits", "Encrypted content, fallback analysis, model uncertainty, and missing data remain visible."],
    ["Preserve the trail", "Hashes, custody events, access history, notes, and exports strengthen the investigation record."],
    ["Keep context attached", "Packets, sessions, protocols, findings, and reports stay scoped to the active case."],
    ["Support human review", "Automation prioritises and organises. An investigator confirms conclusions and next actions."],
    ["Design for regional teams", "English, Hindi, and Gujarati workflows make technical evidence easier to communicate."],
  ];
  const disciplines = [
    ["Forensic workflow", "Evidence intake, custody, case history, and investigator review."],
    ["Packet analysis", "Traffic parsing, session reconstruction, protocols, and encrypted metadata."],
    ["Detection engineering", "Repeatable signatures, anomaly explanations, and attack-path correlation."],
    ["Platform engineering", "Supabase data services, authenticated APIs, storage, queues, and reporting."],
    ["Product systems", "Accessible investigation screens, multilingual UI, and print-safe outputs."],
  ];
  return <PublicShell {...props} className="about-public-site"><main className="about-page">
    <section className="about-hero" id="about-top"><aside /><div className="about-hero-content"><motion.div {...reveal(0)}><SectionLabel>About NETRA</SectionLabel></motion.div><motion.h1 {...reveal(.1)}>A focused system,<br />built with intent.</motion.h1><motion.p {...reveal(.2)}>Network evidence is complex. NETRA is designed to help cybercrime teams preserve what was observed, understand how signals connect, and communicate conclusions without hiding uncertainty.</motion.p><motion.div {...reveal(.3)}><Button asChild className="clip-button cream-button"><Link to="/login" state={{ from: "/app/upload" }}>Open investigation console</Link></Button></motion.div></div></section>
    <section className="about-story"><aside /><div className="about-story-content"><div className="about-operations-image"><MosaicPoster /><span>NETRA / EVIDENCE OPERATIONS</span></div><div className="about-story-grid"><div><SectionLabel>Hello</SectionLabel><h2>Build conclusions from evidence, not opacity.</h2><p>NETRA brings packet capture, protocol evidence, explainable detections, anomaly review, case context, custody history, and reporting into one investigation workflow.</p><p>The system is built around a simple constraint: an investigator should be able to move from a conclusion back to the traffic and reasoning that support it.</p></div><div className="about-metrics"><article><strong>12</strong><span>Detection families</span></article><article><strong>08</strong><span>Decoded protocols</span></article><article><strong>24/7</strong><span>Sensor-ready operations</span></article><article><strong>03</strong><span>Report languages</span></article></div></div></div></section>
    <div className="about-section-system"><aside className="about-rail" aria-label="About sections">{aboutSections.map((label, index) => <a key={label} href={`#about-${index + 1}`} className={activeSection === index ? "active" : ""} aria-current={activeSection === index ? "location" : undefined}><span>0{index + 1}</span>{label}<i style={{ transform: `scaleX(${activeSection === index ? sectionProgress : 0})` }} /></a>)}</aside><div className="about-section-stack">
      <section className="about-values ticket-panel" id="about-1"><SectionLabel index="01">Our values</SectionLabel><div className="about-panel-intro"><h2>Principles that guide how we build.</h2><p>Investigation tooling earns trust through clarity, provenance, and honest boundaries.</p></div><div className="about-value-list">{values.map(([title, body], index) => <article key={title}><span>0{index + 1}</span><div><h3>{title}</h3><p>{body}</p></div><i>+</i></article>)}</div></section>
      <section className="about-disciplines ticket-panel" id="about-2"><SectionLabel index="02">The work</SectionLabel><div className="about-panel-intro"><h2>Disciplines behind the investigation workflow.</h2><p>NETRA combines several technical responsibilities without inventing a public team roster.</p></div><div className="discipline-list">{disciplines.map(([title, body], index) => <article key={title}><span>{String(index + 1).padStart(2, "0")}</span><div><h3>{title}</h3><p>{body}</p></div><strong>NETRA</strong></article>)}</div></section>
      <section className="about-careers ticket-panel" id="about-3"><SectionLabel index="03">Contribute</SectionLabel><div className="about-panel-intro"><h2>Help strengthen evidence-aware infrastructure.</h2><p>Contribution areas are shown as technical workstreams, not fabricated open positions.</p></div><div className="contribution-list">{[["Detection validation", "Rules · benchmarks · explanations"], ["Protocol coverage", "Decoders · sessions · encrypted metadata"], ["Forensic reporting", "Custody · exports · multilingual output"], ["Platform reliability", "Queues · sensors · monitoring · retention"]].map(([title, meta]) => <article key={title}><h3>{title}</h3><span>{meta}</span><ArrowRight /></article>)}</div></section>
      <section className="about-scenario ticket-panel" id="about-4"><SectionLabel index="04">Investigation scenario</SectionLabel><div className="about-panel-intro"><h2>What a connected evidence trail makes possible.</h2><p>A documented workflow replaces an invented endorsement.</p></div><div className="about-scenario-card"><div><span>CASE / DNS-TUNNEL-07</span><blockquote>Periodic queries, encoded labels, repeated timing, and linked destination risk become one reviewable case timeline.</blockquote><p>Observed traffic remains distinct from model-assisted interpretation and investigator conclusions.</p></div><div className="scenario-portrait" aria-label="Abstract monochrome investigator silhouette"><i /></div></div></section>
    </div></div>
  </main></PublicShell>;
}

export function PublicUpdatesPage(props: PublicPageProps) {
  const reveal = useDispatchReveal();
  return <PublicShell {...props} className="updates-public-site"><main className="updates-page">
    <section className="updates-hero"><motion.div {...reveal(0)}><SectionLabel>Threat brief</SectionLabel></motion.div><motion.h1 {...reveal(.1)}>Cyber risk,<br />seen clearly.</motion.h1><motion.p {...reveal(.2)}>How common cyber attacks reach people across India, which patterns matter now, and what to preserve when an incident happens.</motion.p></section>
    <section className="updates-timeline" aria-label="India cyber threat brief">
      {publicUpdates.map((update, index) => <ThreatBriefCard key={update.version} update={update} index={index} />)}
    </section>
  </main></PublicShell>;
}

function ThreatBriefCard({ update, index }: { update: (typeof publicUpdates)[number]; index: number }) {
  const [openDetail, setOpenDetail] = useState<number | null>(null);
  return <article className="threat-entry">
    <aside className="threat-date"><time>{update.date}</time><span>{update.version}</span></aside>
    <motion.div className="threat-card" initial={{ y: 28 }} whileInView={{ y: 0 }} viewport={{ once: true, amount: .12 }} transition={{ duration: .5, delay: Math.min(index * .06, .12) }}>
      <div className={`threat-monitor threat-monitor-${update.visual}`} aria-label={`${update.title} data illustration`}>
        <div className="monitor-chrome"><span>NETRA / INDIA THREAT MONITOR</span><span>{String(index + 1).padStart(2, "0")} / {String(publicUpdates.length).padStart(2, "0")}</span></div>
        <div className="monitor-screen"><div className="monitor-metrics">{update.metrics.map(([value, label]) => <div key={label}><strong>{value}</strong><span>{label}</span></div>)}</div><div className="monitor-signals">{update.signals.map((signal, signalIndex) => <div key={signal}><span>{String(signalIndex + 1).padStart(2, "0")}</span><p>{signal}</p><i style={{ width: `${92 - signalIndex * 12}%` }} /></div>)}</div></div>
      </div>
      <div className="threat-copy"><h2>{update.title}</h2><p>{update.body}</p><p>{update.note}</p><a href={update.sourceUrl} target="_blank" rel="noreferrer">Source: {update.source}</a></div>
      <div className="threat-details">{update.details.map(([title, body], detailIndex) => { const open = openDetail === detailIndex; return <div key={title} className={open ? "open" : ""}><button type="button" onClick={() => setOpenDetail(open ? null : detailIndex)} aria-expanded={open}><span>{detailIndex === 0 ? "KEY SIGNAL" : "GUIDANCE"}</span><strong>{title}</strong><i>{open ? "-" : "+"}</i></button><AnimatePresence initial={false}>{open && <motion.p initial={{ height: 0, opacity: 0 }} animate={{ height: "auto", opacity: 1 }} exit={{ height: 0, opacity: 0 }}>{body}</motion.p>}</AnimatePresence></div>; })}</div>
    </motion.div>
  </article>;
}

export function PublicContactPage(props: PublicPageProps) {
  const [submitted, setSubmitted] = useState(false);
  const contactEmail = String(import.meta.env.VITE_CONTACT_EMAIL ?? "").trim();
  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    if (contactEmail) window.location.href = `mailto:${contactEmail}?subject=${encodeURIComponent(`NETRA enquiry from ${form.get("name")}`)}&body=${encodeURIComponent(String(form.get("message") ?? ""))}`;
    setSubmitted(true);
  }
  return <PublicShell {...props}><main><InteriorHero label="Contact" title="Bring a network-evidence workflow into focus." body="Share the investigation, deployment, or integration context you want to discuss." /><section className="contact-section cream-section"><div><SectionLabel index="01">Enquiry</SectionLabel><h2>Describe the evidence problem.</h2><p>This prototype does not send form data to a third-party service. Configure <code>VITE_CONTACT_EMAIL</code> to open an addressed email draft.</p></div><form onSubmit={submit}><label>Name<Input name="name" required /></label><label>Email<Input name="email" type="email" required /></label><label>Message<Textarea name="message" required /></label><Button type="submit" className="clip-button">Prepare enquiry</Button>{submitted && <p role="status">Your enquiry is ready in the configured email workflow.</p>}</form></section></main></PublicShell>;
}

export function PublicPrivacyPage(props: PublicPageProps) {
  return <LegalPage {...props} title="Privacy" intro="How this prototype handles information in the browser and through configured NETRA services." sections={[["Public website", "The public pages do not require analytics or advertising trackers. A configured YouTube or Vimeo player is loaded only after the visitor requests playback."], ["Investigation data", "Uploaded evidence, case metadata, reports, access records, and authentication data are handled by the configured NETRA backend and storage providers. Deployment operators are responsible for access, retention, and lawful use."], ["Local browser data", "The application may retain the selected language, active case identifier, and authentication session material required by the configured Supabase sign-in flow."], ["Prototype status", "NETRA is a hackathon prototype. This notice is not a claim of certification or suitability for a particular legal process."]]} />;
}

export function PublicTermsPage(props: PublicPageProps) {
  return <LegalPage {...props} title="Terms" intro="Conditions for evaluating the NETRA hackathon prototype." sections={[["Evaluation use", "NETRA is provided for demonstration, research, and controlled evaluation. Validate outputs before relying on them in an operational or legal decision."], ["Investigator responsibility", "Detections and anomaly indicators support review. They do not replace authorization, evidentiary procedure, or an investigator's independent judgment."], ["No decryption claim", "The system analyzes observable traffic and metadata. It does not claim to reveal encrypted payload content."], ["Deployment responsibility", "Operators are responsible for lawful collection, credentials, infrastructure security, retention settings, access control, and incident response in their environment."]]} />;
}

function LegalPage({ title, intro, sections, ...props }: PublicPageProps & { title: string; intro: string; sections: string[][] }) {
  return <PublicShell {...props}><main className="legal-page"><InteriorHero label="NETRA legal" title={title} body={intro} /><article>{sections.map(([heading, body], index) => <section key={heading}><span>0{index + 1}</span><h2>{heading}</h2><p>{body}</p></section>)}</article></main></PublicShell>;
}

export function PublicNotFoundPage(props: PublicPageProps) {
  return <PublicShell {...props}><main className="not-found"><span>404 / ROUTE NOT FOUND</span><h1>The requested path is outside this case.</h1><p>Return to the public NETRA overview or open the investigation console.</p><div><Button asChild className="clip-button"><Link to="/">Return home</Link></Button><Button asChild variant="outline"><Link to="/login">Open console</Link></Button></div></main></PublicShell>;
}
