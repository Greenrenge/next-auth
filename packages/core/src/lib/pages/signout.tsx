import type { Theme } from "../.."

export interface SignoutProps {
  url: URL
  csrfToken: string
  theme: Theme
}

export default function SignoutPage(props: SignoutProps) {
  const { url, csrfToken, theme } = props

  return (
    <div className="signout">
      {theme.brandColor && (
        <style
          dangerouslySetInnerHTML={{
            __html: `
        :root {
          --brand-color: ${theme.brandColor}
        }
      `,
          }}
        />
      )}
      {theme.logo && <img src={theme.logo} alt="Logo" className="logo" />}
      <div className="card">
        <h1>Signout</h1>
        <p>Are you sure you want to sign out?</p>
        <form action={`${url}/signout`} method="POST">
          <input type="hidden" name="csrfToken" value={csrfToken} />
          <button type="submit">Sign out</button>
        </form>
      </div>
    </div>
  )
}
