# Rapport d'incident – Campagne de phishing ANTAI (v1 → v2)

## 1. Identification

* **Type d'incident :** Phishing / Fraud / Credential Harvesting
* **Secteur impacté :** Grand public (France)
* **Usurpation :** ANTAI (Agence nationale de traitement automatisé des infractions)
* **Période observée :** 14–15 avril 2026
* **Statut :** Infrastructures démantelées (v1 et v2)

---

## 2. Résumé exécutif

Une campagne de phishing cible des utilisateurs français en usurpant l'ANTAI afin de collecter des données bancaires via de faux paiements d'amendes.

L'attaquant démontre :

* une **capacité d'adaptation rapide** (rotation d'infrastructure)
* l'usage de **services légitimes (PaaS, CDN)** pour masquer l'activité
* des **techniques d'évasion avancées** (padding, cloaking, anti-bot)

---

## 3. Scoring CVSS

### CVSS v3.1

**Vector String :**

CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N

**Détail :**

| Métrique | Valeur | Justification |
| --- | --- | --- |
| AV (Attack Vector) | Network | Distribution via email |
| AC (Attack Complexity) | Low | Aucune condition technique particulière |
| PR (Privileges Required) | None | Aucun accès préalable requis |
| UI (User Interaction) | Required | Clic sur lien nécessaire |
| S (Scope) | Unchanged | Impact limité au poste utilisateur |
| C (Confidentiality) | High | Exfiltration données bancaires |
| I (Integrity) | High | Possibilité de fraude financière |
| A (Availability) | None | Pas d'impact sur disponibilité |

**Score :** **8.2 (High)**

---

## 4. Mapping MITRE ATT&CK

### Tactiques et techniques

#### Initial Access

* **T1566.001 – Spearphishing Attachment**
* **T1566.002 – Spearphishing Link**

#### Execution

* **T1204.001 – User Execution: Malicious Link**

#### Credential Access

* **T1056 – Input Capture**
* **T1557 – Adversary-in-the-Middle (simulé via phishing web)**

#### Collection

* **T1114 – Email Collection (indirect via phishing)**
* **T1005 – Data from Local System (formulaire utilisateur)**

#### Exfiltration

* **T1041 – Exfiltration Over C2 Channel**
* **T1567 – Exfiltration Over Web Service**

#### Command and Control

* **T1071.001 – Web Protocols (HTTP/HTTPS)**
* **T1090 – Proxy (via CDN / Cloudflare)**

#### Defense Evasion

* **T1027 – Obfuscated/Compressed Files (padding HTML)**
* **T1497 – Virtualization/Sandbox Evasion**
* **T1036 – Masquerading (ANTAI branding)**

---

## 5. Chronologie synthétique

| Date | Phase | Description |
| --- | --- | --- |
| 14/04/2026 | v1 – diffusion | Email `.mx`, lien `appurl.io` |
| 14/04/2026 | v1 – exploitation | Redirection vers `cleverapps.io` |
| 14/04/2026 | v1 – phishing | Page clone ANTAI |
| 15/04/2026 | v1 – réponse | Takedown Clever Cloud |
| 15/04/2026 | v2 – diffusion | Nouveau mail `.edu.mx` |
| 15/04/2026 | v2 – infra | Domaine `paiementexpress.es` |
| 15/04/2026 | v2 – protection | Ajout Cloudflare |
| 16/04/2026 | v2 – réponse | Takedown CDN |

---

## 6. Indicateurs de compromission (IoC)

### Domaines

```
appurl.io
dfdsfsrt.cleverapps.io
paiementexpress.es
service-en-ligne-amendes-antai-gouv-fr.paiementexpress.es
```

### URLs

```
hxxps://appurl[.]io/wgMdQVVusR
hxxps://dfdsfsrt[.]cleverapps[.]io/service/payment-antai/amendes/index[.]php
hxxps://dfdsfsrt[.]cleverapps[.]io/service/payment-antai/amendes/details[.]php
hxxps://appurl[.]io/jp-S8Zjien
hxxps://service-en-ligne-amendes-antai-gouv-fr[.]paiementexpress[.]es/net/details[.]php
hxxps://www[.]paiementexpress[.]es
```

### Emails

```
agonzalez@bilden[.]com[.]mx
alu[.]23130638@correo[.]itlalaguna[.]edu[.]mx
```

### Infrastructure

* Clever Cloud (`*.cleverapps.io`)
* Cloudflare (reverse proxy / protection)

---

## 7. Analyse technique

### 7.1 Chaîne d'attaque

1. Envoi email
2. Redirection via raccourcisseur (`appurl.io`)
3. Landing phishing
4. Saisie données utilisateur
5. Exfiltration backend

---

### 7.2 Techniques d'évasion

#### Padding HTML et injection de liens légitimes

Le corps du message brut contient plusieurs dizaines de lignes vides ainsi que des URLs MSN anodines répétées. Cette technique vise deux objectifs : diluer la densité de termes suspects pour abaisser le score de risque des moteurs bayésiens, et introduire des domaines à bonne réputation dans le contenu analysé afin de tromper les filtres basés sur la réputation des URLs.

#### Encodage Quoted-Printable (RFC 2045)

Le message est encodé en Quoted-Printable, ce qui fragmente les chaînes de caractères sensibles (noms d'organismes, accents, ponctuation) en séquences hexadécimales (`=C3=A9`, `=E2=80=99`, etc.). Cette fragmentation rend l'extraction de signatures textuelles par les moteurs antispam moins fiable.

#### Cloaking et redirections dynamiques

Le lien initial pointe vers un raccourcisseur d'URL tiers (`appurl.io`) qui masque la destination finale. Le contenu servi peut varier selon les attributs de la requête (User-Agent, géolocalisation IP, présence de cookies), permettant de présenter un contenu neutre aux robots d'analyse et le kit de phishing aux victimes réelles.

#### Protection CDN (Cloudflare — type `managed`)

Le site frauduleux est placé derrière un challenge Cloudflare de type `managed`, révélé par les paramètres `_cf_chl_opt` présents dans le code source de la page d'atterrissage. Cette couche remplit trois fonctions : masquer l'adresse IP réelle du serveur hébergeant le kit, bloquer les crawlers automatisés des équipes de threat intelligence, et conférer une apparence de légitimité via le certificat TLS associé au CDN.

---

### 7.3 Exfiltration

#### Méthode de collecte

Les données sont collectées via un formulaire HTML classique soumis en `POST` vers le script `./Assets/php/config/func.php`, hébergé sur le même serveur que le kit. Le formulaire impose des contraintes de saisie côté client (masques jQuery pour la date et le numéro de téléphone) afin de maximiser la qualité des données collectées.

#### Données exfiltrées — étape identité

| Champ | Type |
|---|---|
| Nom | Texte libre |
| Prénom | Texte libre |
| Date de naissance | Texte masqué (JJ/MM/AAAA) |
| Adresse e-mail | Email |
| Numéro de téléphone | Numérique masqué (10 chiffres) |
| Adresse postale | Texte libre |
| Ville | Texte libre |
| Code postal | Texte libre |

#### Tracking en temps réel des victimes

Le kit embarque un script JavaScript (`stutes.js`) qui envoie des pings périodiques toutes les 30 secondes vers un endpoint de suivi (`status/update_status.php`), signalant le statut `online` ou `offline` de la victime ainsi que la page consultée. Ce mécanisme implique l'existence d'un **dashboard d'administration** permettant à l'opérateur de surveiller en temps réel la progression de ses victimes dans le tunnel, et d'intervenir manuellement si nécessaire (relance, modification du contenu affiché).

#### Étape suivante probable — collecte bancaire

L'architecture du kit (tunnel identité → détails → paiement) et le discours affiché sur la page `details.php` (montant de 295,99 €, promesse de remboursement sous 12 h) suggèrent qu'une page de saisie de coordonnées bancaires constitue l'étape finale du tunnel. Cette page n'a pas pu être atteinte sans soumettre de données réelles.

---

## 8. Recommandations CERT

### Réponse immédiate

* Takedown coordonné auprès de l'hébergeur (Clever Cloud) et du CDN (Cloudflare).
* Signalement PHAROS (plateforme nationale de signalement des contenus illicites).
* Notification à l'ANTAI pour communication officielle auprès du public.

### Prévention

* Sensibilisation des utilisateurs : l'ANTAI ne notifie jamais par email sans référence d'infraction explicite.
* Filtrage renforcé des expéditeurs issus de TLDs suspects (`.mx`, `.edu.mx`) se réclamant d'organismes publics français.
* Contrôle DMARC / SPF / DKIM sur les domaines usurpés.
* Alimentation des threat feeds avec les IoC identifiés (section 6).

---

## 9. Attribution

### 9.1 Hypothèse

L'opérateur est vraisemblablement francophone, ce que trahissent la qualité rédactionnelle du contenu du kit, la précision du ciblage (amendes ANTAI, montants cohérents avec la réalité, références législatives reproduites) et le choix d'un vecteur d'attaque très spécifique au contexte français. Le groupe semble en phase de montée en compétences : la maîtrise d'un kit PhaaS relativement sophistiqué contraste avec l'utilisation d'adresses expéditrices en `.mx` et `.edu.mx`, des domaines peu coûteux ou compromis, qui dénotent des ressources encore limitées ou une phase de test.

### 9.2 Observations comportementales

Le décalage entre la v1 et la v2 est instructif. La v1 ressemble davantage à un proof-of-concept déployé prématurément — contenu générique, absence de personnalisation, infrastructure minimale — ce qui suggère qu'elle a pu être envoyée par erreur ou utilisée pour valider la chaîne technique avant le lancement réel. La mise en service rapide de la v2 (nouveau domaine, ajout de Cloudflare, contenu plus élaboré) témoigne d'une capacité de résilience et de rotation d'infrastructure non négligeable.

L'absence de ciblage précis des victimes (pas de personnalisation du message, pas de données préalablement volées exploitées) oriente vers une campagne de type **shotgun** (*spray and pray*) plutôt qu'une opération ciblée. Le choix du thème ANTAI — organisme peu connu du grand public mais dont les notifications génèrent une forte anxiété — est cependant un signe de connaissance du contexte socioculturel français.

---

## 10. Conclusion

Cette campagne illustre une tendance de fond dans l'écosystème de la cybercriminalité francophone : l'accès facilité à des kits de phishing clé en main abaisse considérablement le seuil d'entrée, permettant à des acteurs peu expérimentés de déployer des infrastructures d'attaque multi-couches en quelques heures.

L'analyse de bout en bout révèle un opérateur qui maîtrise les outils sans en avoir encore parfaitement rationalisé l'usage : la sophistication technique du kit (Cloudflare, tracking temps réel, tunnel de collecte structuré, support multilingue) contraste avec des erreurs opérationnelles visibles — adresses expéditrices non crédibles, v1 vraisemblablement déployée par inadvertance, infrastructure hébergée sur un PaaS public facilement démontable.

La rotation rapide vers une v2 après le takedown de la v1 confirme que les délais de réponse actuels, bien qu'efficaces, ne suffisent pas à neutraliser durablement ce type d'acteur. Une approche préventive coordonnée — partage d'IoC en temps réel, notification proactive des hébergeurs et des CDN, communication publique de l'ANTAI — reste la réponse la plus efficace face à des campagnes opportunistes de ce type.

---

*Rapport rédigé à des fins de documentation et de signalement. Tous les IoC sont défangés.*
