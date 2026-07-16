function LoadingSpinner({ message, subtle = false }) {
  return (
    <section
      className={`card loading-card${subtle ? ' loading-card-subtle' : ''}`}
      role="status"
      aria-live="polite"
    >
      <p className="loading-spinner-row">
        <span className="loading-spinner" aria-hidden="true" />
        <span>{message}</span>
      </p>
    </section>
  )
}

export default LoadingSpinner
