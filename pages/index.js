import Image from "next/image";
import { Geist, Geist_Mono } from "next/font/google";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export default function Home() {
  const features = [
    {
      title: "Authentication",
      description: "Complete authentication system with email/password, OTP, and session management"
    },
    {
      title: "Express Integration",
      description: "Custom Express server integrated with Next.js for API routes and server-side logic"
    },
    {
      title: "Prisma ORM",
      description: "Database access using Prisma ORM with PostgreSQL, including migrations and seeding"
    },
    {
      title: "Role-Based Access Control",
      description: "Granular permissions system with role-based access to resources"
    },
    {
      title: "Security",
      description: "Rate limiting, CORS protection, secure cookies, and other security best practices"
    },
    {
      title: "API Testing",
      description: "Comprehensive API tests with test utilities for easy integration testing"
    }
  ];

  return (
    <div
      className={`${geistSans.className} ${geistMono.className} min-h-screen p-8 font-[family-name:var(--font-geist-sans)]`}
    >
      <main className="max-w-6xl mx-auto">
        <div className="text-center mb-16 pt-12">
          <h1 className="text-4xl md:text-6xl font-bold mb-4">Next.js + Express + Prisma</h1>
          <h2 className="text-2xl md:text-3xl mb-8 text-gray-600 dark:text-gray-300">Full-Stack Authentication Template</h2>
          <p className="text-lg mb-8 max-w-3xl mx-auto">
            A complete starter template for building secure, production-ready applications with Next.js, Express, and Prisma
          </p>
          <div className="flex flex-wrap gap-4 justify-center">
            <a
              href="https://github.com/Code-Decoders/cd-next-express-template"
              target="_blank"
              rel="noopener noreferrer"
              className="rounded-md bg-black dark:bg-white text-white dark:text-black px-6 py-3 font-medium text-lg hover:bg-gray-800 dark:hover:bg-gray-200 transition"
            >
              View on GitHub
            </a>
            <a
              href="/api/auth/login"
              className="rounded-md border border-gray-300 dark:border-gray-700 px-6 py-3 font-medium text-lg hover:bg-gray-100 dark:hover:bg-gray-800 transition"
            >
              Demo Login
            </a>
          </div>
        </div>

        <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-8 mb-16">
          {features.map((feature, index) => (
            <div key={index} className="border border-gray-200 dark:border-gray-700 rounded-lg p-6 hover:shadow-md transition">
              <h3 className="text-xl font-bold mb-2">{feature.title}</h3>
              <p className="text-gray-600 dark:text-gray-300">{feature.description}</p>
            </div>
          ))}
        </div>

        <div className="bg-gray-100 dark:bg-gray-800 p-8 rounded-lg mb-16">
          <h2 className="text-2xl font-bold mb-4">Getting Started</h2>
          <div className="font-mono text-sm bg-black dark:bg-gray-900 text-white p-4 rounded mb-4 overflow-x-auto">
            <p>git clone https://github.com/Code-Decoders/cd-next-express-template.git</p>
            <p>cd nextjs-express-prisma-auth-template</p>
            <p>npm install</p>
            <p>npm run dev</p>
          </div>
          <p>Check the <a href="https://github.com/Code-Decoders/cd-next-express-template.git" className="text-blue-600 dark:text-blue-400 hover:underline">README</a> for complete setup instructions.</p>
        </div>

        <div className="border-t border-gray-200 dark:border-gray-700 pt-8">
          <h2 className="text-2xl font-bold mb-4">API Routes</h2>
          <div className="overflow-x-auto">
            <table className="min-w-full border-collapse">
              <thead>
                <tr className="border-b dark:border-gray-700">
                  <th className="py-2 px-4 text-left">Endpoint</th>
                  <th className="py-2 px-4 text-left">Method</th>
                  <th className="py-2 px-4 text-left">Description</th>
                </tr>
              </thead>
              <tbody>
                <tr className="border-b dark:border-gray-700">
                  <td className="py-2 px-4 font-mono text-sm">/api/auth/register</td>
                  <td className="py-2 px-4">POST</td>
                  <td className="py-2 px-4">Register a new user</td>
                </tr>
                <tr className="border-b dark:border-gray-700">
                  <td className="py-2 px-4 font-mono text-sm">/api/auth/login</td>
                  <td className="py-2 px-4">POST</td>
                  <td className="py-2 px-4">Login with email/password</td>
                </tr>
                <tr className="border-b dark:border-gray-700">
                  <td className="py-2 px-4 font-mono text-sm">/api/auth/logout</td>
                  <td className="py-2 px-4">POST</td>
                  <td className="py-2 px-4">Logout current user</td>
                </tr>
                <tr className="border-b dark:border-gray-700">
                  <td className="py-2 px-4 font-mono text-sm">/api/auth/request-otp</td>
                  <td className="py-2 px-4">POST</td>
                  <td className="py-2 px-4">Request one-time password</td>
                </tr>
                <tr>
                  <td className="py-2 px-4 font-mono text-sm">/api/auth/me</td>
                  <td className="py-2 px-4">GET</td>
                  <td className="py-2 px-4">Get current user info</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </main>

      <footer className="mt-20 pt-8 border-t border-gray-200 dark:border-gray-700 text-center">
        <div className="flex gap-8 flex-wrap items-center justify-center mb-8">
          <a
            className="flex items-center gap-2 hover:underline hover:underline-offset-4"
            href="https://nextjs.org"
            target="_blank"
            rel="noopener noreferrer"
          >
            <Image
              src="/next.svg"
              alt="Next.js logo"
              width={80}
              height={20}
              className="dark:invert"
            />
          </a>
          <a
            className="flex items-center gap-2 hover:underline hover:underline-offset-4"
            href="https://expressjs.com"
            target="_blank"
            rel="noopener noreferrer"
          >
            Express.js
          </a>
          <a
            className="flex items-center gap-2 hover:underline hover:underline-offset-4"
            href="https://prisma.io"
            target="_blank"
            rel="noopener noreferrer"
          >
            Prisma
          </a>
        </div>
        <p className="text-sm text-gray-600 dark:text-gray-400">
          © {new Date().getFullYear()} Next.js Express Template. MIT License.
        </p>
      </footer>
    </div>
  );
}
