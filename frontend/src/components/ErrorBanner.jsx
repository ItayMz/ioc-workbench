function ErrorBanner({ message }) {
  if (!message) {
    return null
  }

  return (
    <section className="card error-banner" role="alert" aria-live="assertive">
      <strong>Request failed.</strong> {message}
    </section>
  )
}

export default ErrorBanner
