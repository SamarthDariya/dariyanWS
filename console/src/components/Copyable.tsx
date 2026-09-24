import { useState } from "react";

/** A value worth copying rather than retyping — an ARN, a key id, a secret shown once. */
export function Copyable({ value, className }: { value: string; className?: string }) {
  const [copied, setCopied] = useState(false);

  async function copy() {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      setTimeout(() => setCopied(false), 1400);
    } catch {
      // Clipboard access can be refused, and a console that throws over a convenience is worse
      // than one where the button quietly does nothing. The value is on screen either way.
    }
  }

  return (
    <button className={`ghost ${className ?? ""}`} onClick={copy} type="button">
      {copied ? "copied" : "copy"}
    </button>
  );
}
