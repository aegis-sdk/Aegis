export const metadata = {
  title: "Aegis Chatbot",
  description: "Next.js chatbot with Aegis prompt injection defense",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body style={{ margin: 0, fontFamily: "system-ui, sans-serif" }}>{children}</body>
    </html>
  );
}
