import { randomBytes } from "crypto"
import { AdapterSession, AdapterUser } from "src/adapters"
import { JWT } from "src/jwt"
import { InternalOptions } from "../../../lib/types"
import { SessionStore, SessionToken } from "../cookie"
import { hashToken } from "../utils"

/**
 * Starts an e-mail login flow, by generating a token,
 * and sending it to the user's e-mail (with the help of a DB adapter)
 */
export default async function email(
  identifier: string,
  options: InternalOptions<"email">,
  sessionStore: SessionStore
): Promise<String | undefined> {
  const {
    url,
    adapter,
    provider,
    logger,
    callbackUrl,
    jwt,
    session: { strategy: sessionStrategy },
  } = options
  // Generate token
  const token =
    (await provider.generateVerificationToken?.()) ??
    randomBytes(32).toString("hex")

  const ONE_DAY_IN_SECONDS = 86400
  const expires = new Date(
    Date.now() + (provider.maxAge ?? ONE_DAY_IN_SECONDS) * 1000
  )

  const sessionToken: SessionToken = sessionStore.value
  const useJwtSession = sessionStrategy === "jwt"

  let session: AdapterSession | JWT | null = null
  let user: AdapterUser | null = null

  if (!adapter) {
    throw Error("Adapter is not configured")
  }

  const { getUser, getSessionAndUser, getUserByAccount, getUserByEmail } =
    adapter

  if (useJwtSession) {
    try {
      session = await jwt.decode({ ...jwt, token: sessionToken })
      if (session && "sub" in session && session.sub) {
        user = await getUser(session.sub)
      }
    } catch {
      // If session can't be verified, treat as no session
    }
  } else {
    const userAndSession = await getSessionAndUser(sessionToken)
    if (userAndSession) {
      session = userAndSession.session
      user = userAndSession.user
    }
  }

  if (!user?.id) {
    throw new Error("not found user")
  }

  const userLinkedToEmail = await getUserByAccount({
    providerAccountId: identifier,
    provider: "email",
  })

  if (userLinkedToEmail?.id?.toString() === user.id.toString()) {
    //user already link
    return "link_success"
  }
  if (!!userLinkedToEmail?.id?.toString()) {
    //email already linked to another user
    return "link_taken"
  }

  const userHasSameEmail = await getUserByEmail(identifier)
  if (
    userHasSameEmail &&
    userHasSameEmail.id.toString() !== user.id.toString()
  ) {
    // someone else OAuth has the same email
    return "link_taken"
  }

  //TODO: GREEN many users may have the same identifier here
  // Save in database
  // @ts-expect-error
  await adapter.createVerificationToken({
    identifier,
    userId: user.id, //TODO: GREEN put the requester id in here ??
    token: hashToken(token, options),
    expires,
  })

  // Generate a link with email, unhashed token and callback url
  const params = new URLSearchParams({ callbackUrl, token, email: identifier })
  const _url = `${url}/callback/${provider.id}?${params}`

  try {
    // Send to user
    await provider.sendVerificationRequest({
      identifier,
      token,
      expires,
      url: _url,
      provider,
    })
  } catch (error) {
    logger.error("SEND_VERIFICATION_EMAIL_ERROR", {
      identifier,
      url,
      userId: user.id,
      error: error as Error,
    })
    throw new Error("SEND_VERIFICATION_EMAIL_ERROR")
  }
}
