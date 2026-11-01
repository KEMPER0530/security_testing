import { useEffect, useId, useRef, useState } from "react";
import { createPortal } from "react-dom";

export function InfoTooltip({ label, text }: { label: string; text: string }) {
  const id = useId();
  const button = useRef<HTMLButtonElement>(null);
  const popup = useRef<HTMLDivElement>(null);
  const closeTimer = useRef<number | undefined>(undefined);
  const [open, setOpen] = useState(false);
  const [position, setPosition] = useState({ left: 12, top: 12 });
  const keepOpen = () => {
    window.clearTimeout(closeTimer.current);
    setOpen(true);
  };
  const closeSoon = () => {
    if (document.activeElement === button.current) return;
    closeTimer.current = window.setTimeout(() => setOpen(false), 150);
  };
  useEffect(() => () => window.clearTimeout(closeTimer.current), []);
  useEffect(() => {
    if (!open) return;
    const reposition = () => {
      const rect = button.current?.getBoundingClientRect();
      const tip = popup.current?.getBoundingClientRect();
      if (!rect || !tip) return;
      setPosition({
        left: Math.max(
          12,
          Math.min(rect.left, window.innerWidth - tip.width - 12),
        ),
        top: Math.max(
          12,
          rect.bottom + tip.height + 12 < window.innerHeight
            ? rect.bottom + 8
            : rect.top - tip.height - 8,
        ),
      });
    };
    const dismiss = (event: KeyboardEvent) => {
      if (event.key === "Escape") setOpen(false);
    };
    const outside = (event: PointerEvent) => {
      if (
        !button.current?.contains(event.target as Node) &&
        !popup.current?.contains(event.target as Node)
      )
        setOpen(false);
    };
    reposition();
    window.addEventListener("resize", reposition);
    window.addEventListener("scroll", reposition, true);
    document.addEventListener("keydown", dismiss);
    document.addEventListener("pointerdown", outside);
    return () => {
      window.removeEventListener("resize", reposition);
      window.removeEventListener("scroll", reposition, true);
      document.removeEventListener("keydown", dismiss);
      document.removeEventListener("pointerdown", outside);
    };
  }, [open]);
  return (
    <span
      className="help-control"
      onMouseEnter={keepOpen}
      onMouseLeave={closeSoon}
    >
      <button
        ref={button}
        type="button"
        className="help-button"
        aria-label={label}
        aria-expanded={open}
        aria-describedby={open ? id : undefined}
        onClick={() => setOpen(true)}
        onFocus={() => setOpen(true)}
        onBlur={() => setOpen(false)}
      >
        ?
      </button>
      {open &&
        createPortal(
          <div
            ref={popup}
            id={id}
            role="tooltip"
            className="info-tooltip"
            style={position}
            onMouseEnter={keepOpen}
            onMouseLeave={closeSoon}
          >
            {text}
          </div>,
          document.body,
        )}
    </span>
  );
}
