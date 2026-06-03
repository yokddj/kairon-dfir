import { type ReactNode } from "react";
import Sidebar from "./Sidebar";
import Topbar from "./Topbar";
import ToastViewport from "./ToastViewport";

type Props = { children: ReactNode };

export default function Layout({ children }: Props) {
  return (
    <div className="min-h-screen overflow-x-hidden bg-[radial-gradient(circle_at_top,_rgba(79,209,197,0.08),_transparent_30%),linear-gradient(180deg,_#07141b_0%,_#081118_100%)] text-ink">
      <ToastViewport />
      <div className="flex min-h-screen w-full overflow-x-hidden">
        <Sidebar />
        <div className="flex min-h-screen min-w-0 flex-1 flex-col">
          <Topbar />
          <main className="min-w-0 flex-1 overflow-x-hidden px-4 py-5 md:px-6 md:py-6 xl:px-8">{children}</main>
        </div>
      </div>
    </div>
  );
}
