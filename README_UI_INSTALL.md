# VendorSentinel AI — Light UI Pack

This pack changes only the presentation layer.

## Replace / add these folders

Copy the included `templates` and `static` folders into the root of your
working Flask project.

Your project should contain:

- `templates/base.html`
- `templates/dashboard.html`
- `templates/vendors.html`
- `templates/vendor_detail.html`
- `templates/alerts.html`
- `templates/compliance.html`
- `templates/reports.html`
- `static/css/app.css`
- `static/js/app.js`

Do not replace `app.py`, the database, algorithms or services.

## Run

```powershell
.\.venv\Scripts\python.exe app.py
```

Then test:

- `/`
- `/vendors`
- `/alerts`
- `/compliance`
- `/reports`
- `/vendors/VND-1252`

The UI uses GSAP through a CDN. If the CDN is unavailable, the application
still works; only entrance animations are skipped.
