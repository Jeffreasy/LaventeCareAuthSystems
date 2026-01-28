🛡️ LaventeCare Auth Systems: Systeemoverzicht & Architectuur
LaventeCare Auth Systems is een high-performance, security-first Identity & Access Management (IAM) backend. Het fungeert als de centrale "Headless" Auth Provider voor een gedistribueerd ecosysteem van applicaties, variërend van webfrontends tot IoT-hardware.

🎯 De Missie
Het systeem is ontworpen om de volledige last van Authenticatie, Autorisatie en Multi-Tenancy te abstraheren van satelliet-applicaties. Hierdoor kunnen andere projecten direct gebruikmaken van een "hardened" security-infrastructuur zonder zelf complexe beveiligingslogica te implementeren.

🏛️ Kernfunctionaliteiten
Identiteitsbeheer (Identity Management)

Secure Storage: Wachtwoorden worden gehasht met Bcrypt (Cost 12) volgens de 2026-standaarden.

MFA-First: Ingebouwde ondersteuning voor TOTP (Time-based One-Time Passwords) en cryptografisch gegenereerde backup-codes.

Dual-Token Systeem: Gebruik van short-lived JWT’s voor toegang en geroteerde, opaque Refresh Tokens voor sessiebeheer.

Strict Isolation (Multi-Tenancy)

Context-Aware: Elke request wordt gevalideerd tegen een TenantID.

Fortress Database: Gebruik van PostgreSQL met actieve Row Level Security (RLS) om datalekken tussen cliënten op hardwareniveau te voorkomen.

Logical Separation: Data is strikt gescheiden via een memberships structuur, waardoor gebruikers veilig lid kunnen zijn van meerdere organisaties (tenants).

Toegangscontrole (RBAC)

Claims-Based: Gebruikersrollen (admin, editor, viewer) zijn ingebed in de JWT-claims voor zero-latency autorisatiecontroles.

Hierarchische Rechten: Een strikt RBAC-model dwingt het principe van 'least privilege' af over alle API-endpoints.

Integriteit & Verantwoording (Audit Logging)

Immutable Logs: Elke kritieke actie (login, wijziging, verwijdering) wordt vastgelegd in een append-only audit-tabel.

Database Enforcement: SQL-level restricties voorkomen dat audit-logs gemanipuleerd of verwijderd kunnen worden, essentieel voor compliance (GDPR/SOC2).

🚀 De "Anti-Gravity" Pillars (Security Philosophy)
Input is Toxic: Geen enkele byte wordt vertrouwd. Strict type-checking en validatie vinden plaats bij de poort via sqlc en strikte JSON-decoders.

Silence is Golden: Het systeem lekt nooit interne foutmeldingen of stack-traces aan de buitenwereld. Monitoring gebeurt intern via gestructureerde logging (slog) en Sentry.

Race Conditions are Fatal: State wordt uitsluitend beheerd via transactionele database-operaties om inconsistenties te voorkomen.

The Janitor: Een autonome background worker zuivert het systeem continu van verlopen sessies en tokens, wat de aanvalsoppervlakte minimaliseert.

📂 Ecosysteem Integratie
De backend is technologieneutraal en ontsluit zijn kracht via een gestandaardiseerde REST API. Dit maakt het de ideale backbone voor:

Web-applicaties: (Astro, React, Next.js) via beveiligde cookies of headers.

IoT-Devices: (ESP32/C++) via lichtgewicht token-gebaseerde telemetrie-endpoints.

Automatisering: Achtergrondprocessen die handelen binnen een specifiek tenant-bereik.