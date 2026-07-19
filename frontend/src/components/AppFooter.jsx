import Icon from './Icon.jsx'

function AppFooter({ onOpenShortcuts }) {
  return (
    <footer className="card app-footer">
      <div className="app-footer-top">
        <p className="app-footer-title">IOC Workbench</p>
        <p className="muted">Built for SOC Operations</p>
        <p className="muted">Developed by Itay Mazor</p>
      </div>
      <div className="app-footer-bottom">
        <span>IOC Workbench v1.3</span>
        <button type="button" className="footer-link-button" onClick={onOpenShortcuts}>
          <Icon name="about" className="inline-icon" /> About
        </button>
      </div>
    </footer>
  )
}

export default AppFooter
