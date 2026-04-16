# Rapport d'incident – Campagne de phishing ANTAI (v1 → v2)

## 1. Identification

- **Type d’incident :** Phishing / Fraud / Credential Harvesting
- **Secteur impacté :** Grand public (France)
- **Usurpation :** ANTAI (Agence nationale de traitement automatisé des infractions)
- **Période observée :** 14–15 avril 2026
- **Statut :** Infrastructures démantelées (v1 et v2)

---

## 2. Résumé exécutif

Une campagne de phishing cible des utilisateurs français en usurpant l’ANTAI afin de collecter des données bancaires via de faux paiements d’amendes.

L’attaquant démontre :
- une **capacité d’adaptation rapide** (rotation d’infrastructure)
- l’usage de **services légitimes (PaaS, CDN)** pour masquer l’activité
- des **techniques d’évasion avancées** (padding, cloaking, anti-bot)

---

## 3. Scoring CVSS

### CVSS v3.1

**Vector String :**

CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N


**Détail :**

| Métrique | Valeur | Justification |
|----------|--------|--------------|
| AV (Attack Vector) | Network | Distribution via email |
| AC (Attack Complexity) | Low | Aucune condition technique particulière |
| PR (Privileges Required) | None | Aucun accès préalable requis |
| UI (User Interaction) | Required | Clic sur lien nécessaire |
| S (Scope) | Unchanged | Impact limité au poste utilisateur |
| C (Confidentiality) | High | Exfiltration données bancaires |
| I (Integrity) | High | Possibilité de fraude financière |
| A (Availability) | None | Pas d’impact sur disponibilité |

**Score :** **8.2 (High)**

---

## 4. Mapping MITRE ATT&CK

### Tactiques et techniques

#### Initial Access
- **T1566.001 – Spearphishing Attachment**
- **T1566.002 – Spearphishing Link**

#### Execution
- **T1204.001 – User Execution: Malicious Link**

#### Credential Access
- **T1056 – Input Capture**
- **T1557 – Adversary-in-the-Middle (simulé via phishing web)**

#### Collection
- **T1114 – Email Collection (indirect via phishing)**
- **T1005 – Data from Local System (formulaire utilisateur)**

#### Exfiltration
- **T1041 – Exfiltration Over C2 Channel**
- **T1567 – Exfiltration Over Web Service**

#### Command and Control
- **T1071.001 – Web Protocols (HTTP/HTTPS)**
- **T1090 – Proxy (via CDN / Cloudflare)**

#### Defense Evasion
- **T1027 – Obfuscated/Compressed Files (padding HTML)**
- **T1497 – Virtualization/Sandbox Evasion**
- **T1036 – Masquerading (ANTAI branding)**

---

## 5. Chronologie synthétique

| Date | Phase | Description |
|------|------|------------|
| 14/04/2026 | v1 – diffusion | email `.mx`, lien `appurl.io` |
| 14/04/2026 | v1 – exploitation | Redirection vers `cleverapps.io` |
| 14/04/2026 | v1 – phishing | Page clone ANTAI |
| 16/04/2026 | v1 – réponse | Takedown Clever Cloud |
| 15/04/2026 | v2 – diffusion | Nouveau mail `.edu.mx` |
| 15/04/2026 | v2 – infra | Domaine `paiementexpress.es` |
| 15/04/2026 | v2 – protection | Ajout Cloudflare |
| 16/04/2026 | v2 – réponse | Takedown CDN |

---

## 6. Indicateurs de compromission (IoC)

### Domaines

appurl.io  
dfdsfsrt.cleverapps.io  
paiementexpress.es  
service-en-ligne-amendes-antai-gouv-fr.paiementexpress.es
paiementexpress.es (site façade e-commerce/solution paiement pro)


### URLs

hxxps://appurl[.]io/wgMdQVVusR

hxxps://dfdsfsrt[.]cleverapps[.]io/service/payment-antai/amendes/index[.]php

hxxps://dfdsfsrt[.]cleverapps[.]io/service/payment-antai/amendes/details[.]php

hxxps://appurl[.]io/jp-S8Zjien

hxxps://service-en-ligne-amendes-antai-gouv-fr[.]paiementexpress[.]es/net/details[.]php

hxxps://www[.]paiementexpress[.]es

hxxps://www[.]paiementexpress[.]es


### Emails

agonzalez@bilden[.]com[.]mx

alu[.]23130638@correo[.]itlalaguna[.]edu[.]mx


### Infrastructure
- Clever Cloud (`*.cleverapps.io`)
- Cloudflare (reverse proxy / protection)

---

## 7. Analyse technique

### 7.1 Chaîne d’attaque

1. Envoi email
2. Redirection via raccourcisseur (`appurl.io`)
3. Landing phishing
4. Saisie données utilisateur
5. Exfiltration backend

---

### 7.2 Techniques d’évasion

- Padding HTML massif
- Injection de liens légitimes (MSN)
- Cloaking (User-Agent / IP)
- Redirections dynamiques
- Protection CDN (Cloudflare)

---

### 7.3 Exfiltration

- Méthode : POST HTTP(S)
- Destination : serveur phishing
- Données exfiltrées :
  - identité
  - coordonnées bancaires
  - potentiellement OTP

---

## 8. Recommandations CERT

### Réponse
- takedown coordonné :
  - hébergeur
  - CDN

### Prévention
- sensibilisation utilisateurs
- filtrage emails `.mx` suspects
- contrôle DMARC/SPF/DKIM

---

## 9. Conclusion

Cette campagne démontre :

une industrialisation du phishing ANTAI
une capacité de régénération rapide
une montée en sophistication (Cloudflare, cloaking)

Le modèle observé est compatible avec des opérations opportunistes semi-automatisées, avec réutilisation d’outils et d’infrastructures.
