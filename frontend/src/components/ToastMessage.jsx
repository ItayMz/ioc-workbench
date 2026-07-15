function ToastMessage({ toast }) {
  if (!toast) {
    return null
  }

  return (
    <div className={`copy-toast copy-toast-${toast.tone || 'success'}`} role="status" aria-live="polite">
      {toast.message}
    </div>
  )
}

export default ToastMessage
