# Mapping D3FEND – Campagne Phishing ANTAI (v1 → v2)

## 1. Vue d’ensemble

Ce mapping associe les techniques adverses observées aux **contre-mesures D3FEND** afin de faciliter :
- la détection SOC
- le durcissement des contrôles
- la réponse à incident

---

## 2. Mapping par phase d’attaque

### 2.1 Initial Access – Phishing

#### Technique adverse
- Email/SMS phishing (lien raccourci)
- Usurpation ANTAI

#### D3FEND

- **Email Filtering (D3-EMF)**
  - Filtrage des domaines `.mx` suspects
  - Détection d’usurpation ANTAI

- **URL Analysis (D3-URLA)**
  - Inspection des raccourcisseurs (`appurl.io`)
  - Expansion automatique des liens

- **Sender Verification (D3-SVF)**
  - SPF / DKIM / DMARC enforcement

---

### 2.2 Delivery – Redirection & Landing

#### Technique adverse
- Chaîne de redirection
- Infrastructure cloud légitime

#### D3FEND

- **Network Traffic Filtering (D3-NTF)**
  - Blocage domaines malveillants
  - Filtrage DNS

- **Domain Reputation Analysis (D3-DRA)**
  - Détection domaines récents / jetables
  - Scoring réputation

- **TLS Inspection (D3-TLSI)**
  - Inspection trafic HTTPS vers domaines suspects

---

### 2.3 Execution – Interaction utilisateur

#### Technique adverse
- Clic utilisateur
- Chargement page phishing

#### D3FEND

- **User Behavior Monitoring (D3-UBM)**
  - Détection clic sur lien suspect

- **Browser Isolation (D3-BI)**
  - Isolation du rendu web (RBI)

- **Content Disarm & Reconstruction (D3-CDR)**
  - Neutralisation contenu HTML malveillant

---

### 2.4 Credential Access – Saisie utilisateur

#### Technique adverse
- Formulaire phishing (CB, identité)

#### D3FEND

- **Input Validation Monitoring (D3-IVM)**
  - Détection soumission vers domaine suspect

- **Credential Theft Detection (D3-CTD)**
  - Surveillance exfiltration credentials

- **Multi-Factor Authentication (D3-MFA)**
  - Réduction impact compromission

---

### 2.5 Exfiltration

#### Technique adverse
- POST HTTPS vers backend phishing

#### D3FEND

- **Data Loss Prevention (D3-DLP)**
  - Détection fuite données sensibles

- **Encrypted Traffic Analysis (D3-ETA)**
  - Analyse comportementale HTTPS

- **Network Flow Analysis (D3-NFA)**
  - Détection flux anormaux vers nouveaux domaines

---

### 2.6 Command & Control (C2)

#### Technique adverse
- HTTP(S) via CDN (Cloudflare)

#### D3FEND

- **Traffic Pattern Analysis (D3-TPA)**
  - Détection patterns atypiques

- **Proxy Filtering (D3-PF)**
  - Blocage domaines derrière CDN suspects

- **Domain Fronting Detection (D3-DFD)**
  - Détection usage abusif CDN

---

### 2.7 Defense Evasion

#### Technique adverse
- Padding HTML
- Cloaking (UA/IP)
- Anti-bot (Cloudflare)

#### D3FEND

- **File Content Analysis (D3-FCA)**
  - Détection anomalies HTML (padding massif)

- **Deception Environment (D3-DE)**
  - Sandbox réaliste (bypass cloaking)

- **Dynamic Analysis (D3-DA)**
  - Exécution avec différents User-Agents

---

### 2.8 Infrastructure Resilience (v2)

#### Technique adverse
- Rotation rapide domaines
- CDN protection

#### D3FEND

- **Threat Intelligence Sharing (D3-TIS)**
  - Partage IoC en temps réel

- **Automated Takedown (D3-ATD)**
  - Orchestration réponse (CDN / registrar)

- **Infrastructure Mapping (D3-IM)**
  - Cartographie campagnes multi-domaines

---

## 3. Mapping synthétique

| Phase | Technique | D3FEND |
|------|----------|--------|
| Initial Access | Phishing | D3-EMF, D3-URLA, D3-SVF |
| Delivery | Redirection | D3-NTF, D3-DRA |
| Execution | Clic utilisateur | D3-UBM, D3-BI |
| Credential Access | Formulaire phishing | D3-CTD, D3-MFA |
| Exfiltration | POST HTTPS | D3-DLP, D3-ETA |
| C2 | HTTPS via CDN | D3-TPA, D3-PF |
| Evasion | Cloaking/padding | D3-FCA, D3-DA |
| Résilience | Rotation infra | D3-TIS, D3-ATD |

---

## 4. Recommandations SOC (opérationnelles)

### Détection rapide
- Alertes sur :
  - domaines récemment créés
  - raccourcisseurs d’URL
  - HTML volumineux anormal

### Hunting
- requêtes DNS vers :

*.cleverapps.io
*.paiementexpress.es


---

## 5. Conclusion

Le mapping D3FEND met en évidence que :

- les contrôles **email + DNS + web** sont critiques
- la **visibilité sur trafic chiffré** est indispensable
- la **réactivité (takedown + TI)** est déterminante face à la rotation rapide

