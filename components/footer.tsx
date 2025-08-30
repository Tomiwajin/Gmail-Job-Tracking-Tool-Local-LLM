import Link from "next/link";

export function Footer() {
  return (
    <footer className="border-t mt-auto bg-background">
      <div className="container mx-auto px-4 py-6">
        <div className="flex flex-col md:flex-row justify-between items-center space-y-4 md:space-y-0">
          <div className="text-sm text-muted-foreground">
            © 2025 Job Application Tracker. All rights reserved.
          </div>
          <div className="flex space-x-6 text-sm">
            <a
              href="https://github.com/Tomiwajin/Gmail-Job-Tracking-Tool-Local-LLM.git"
              target="_blank"
              rel="noopener noreferrer"
              className="text-muted-foreground hover:text-foreground transition-colors"
            >
              GitHub
            </a>
          </div>
        </div>
      </div>
    </footer>
  );
}
