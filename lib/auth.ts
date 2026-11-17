import { createHash, timingSafeEqual } from "node:crypto";
import { headers } from "next/headers";
import NextAuth, { type NextAuthConfig } from "next-auth";
import Nodemailer from "next-auth/providers/nodemailer";
import Resend from "next-auth/providers/resend";
import { PrismaAdapter } from "@auth/prisma-adapter";
import { prisma } from "@/lib/db/client";
import { ensureWorkspaceForUser, getPrimaryWorkspace } from "@/lib/workspace";
import { isEmailAllowedToSignIn } from "@/lib/env";

type AdapterPrismaClient = Parameters<typeof PrismaAdapter>[0];

const emailFrom = process.env.EMAIL_FROM ?? "OpenReply <login@example.com>";
// Setting EMAIL_SERVER switches magic links to your own SMTP server, for
// self-hosters who do not want a third-party mail service. Resend stays the
// default, so an existing deployment is unaffected.
const smtpServer = process.env.EMAIL_SERVER;

/**
 * Provider id the login form has to sign in with. It differs per transport,
 * so it is derived here rather than hardcoded at the call site.
 */
export const EMAIL_PROVIDER_ID = smtpServer ? "nodemailer" : "resend";

export const authConfig = {
  adapter: PrismaAdapter(prisma as unknown as AdapterPrismaClient),
  providers: [
    smtpServer
      ? Nodemailer({ server: smtpServer, from: emailFrom })
      : Resend({
          apiKey: process.env.RESEND_API_KEY ?? "missing-resend-api-key",
          from: emailFrom,
        }),
  ],
  callbacks: {
    // Runs before the magic link is sent, so a blocked address never receives
    // one, and again when the link is verified.
    async signIn({ user }) {
      return isEmailAllowedToSignIn(user?.email);
    },
    async session({ session, user }) {
      if (session.user) {
        session.user.id = user.id;
      }
      return session;
    },
  },
  events: {
    async createUser({ user }) {
      if (user.id) {
        await ensureWorkspaceForUser(user.id, user.email);
      }
    },
  },
  pages: {
    signIn: "/login",
    verifyRequest: "/verify-request",
  },
  session: {
    strategy: "database",
  },
  trustHost: true,
  secret: process.env.NEXTAUTH_SECRET,
} satisfies NextAuthConfig;

export const { handlers, auth, signIn, signOut } = NextAuth(authConfig);

/**
 * Programmatic access for trusted automation (e.g. an MCP server run by the
 * workspace owner). Enabled only when both OPENREPLY_API_KEY (>= 32 chars) and
 * OPENREPLY_API_USER_EMAIL are set; the key then acts as that user. Compared in
 * constant time. Without the env vars this is a no-op.
 */
async function getApiKeyUserId(): Promise<string | null> {
  const key = process.env.OPENREPLY_API_KEY?.trim();
  const email = process.env.OPENREPLY_API_USER_EMAIL?.trim().toLowerCase();
  if (!key || key.length < 32 || !email) return null;

  let header: string | null = null;
  try {
    header = (await headers()).get("authorization");
  } catch {
    return null; // called outside a request scope
  }
  const match = header?.match(/^Bearer\s+(.+)$/i);
  if (!match) return null;

  const given = createHash("sha256").update(match[1].trim()).digest();
  const expected = createHash("sha256").update(key.trim()).digest();
  if (!timingSafeEqual(given, expected)) {
    console.warn("[api-key] rejected: key does not match OPENREPLY_API_KEY");
    return null;
  }

  const user = await prisma.user.findFirst({
    where: { email: { equals: email, mode: "insensitive" } },
    select: { id: true },
  });
  if (!user) {
    console.warn("[api-key] key ok but no user found for OPENREPLY_API_USER_EMAIL");
  }
  return user?.id ?? null;
}

export async function getCurrentUserId(): Promise<string | null> {
  const apiUserId = await getApiKeyUserId();
  if (apiUserId) return apiUserId;
  const session = await auth();
  return session?.user?.id ?? null;
}

export async function getCurrentWorkspaceId(): Promise<string | null> {
  const userId = await getCurrentUserId();
  if (!userId) return null;

  const workspace = await getPrimaryWorkspace(userId);
  if (workspace) return workspace.id;

  const user = await prisma.user.findUnique({
    where: { id: userId },
    select: { email: true },
  });

  const createdWorkspace = await ensureWorkspaceForUser(userId, user?.email);
  return createdWorkspace.id;
}
