# Rapport d'incident – Campagne de phishing ANTAI (v1 → v2)

## 1. Identification

* **Type d'incident :** Phishing / Fraud / Credential Harvesting
* **Secteur impacté :** Grand public (France)
* **Usurpation :** ANTAI (Agence nationale de traitement automatisé des infractions)
* **Période observée :** 14–15 avril 2026
* **Statut :** Infrastructure v1 démantelée — infrastructure v2 **toujours active** malgré les signalements

---

## 2. Résumé exécutif

Une campagne de phishing cible des utilisateurs français en usurpant l'ANTAI afin de collecter des données bancaires via de faux paiements d'amendes.

L'attaquant démontre :

* une **capacité d'adaptation rapide** (rotation d'infrastructure)
* l'usage de **services légitimes (PaaS, CDN)** pour masquer l'activité
* des **techniques d'évasion avancées** (padding, cloaking, blocage IP actif en temps réel)

---

## 3. Scoring CVSS

### CVSS v3.1

**Vector String :**

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N
```

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
* **T1562.006 – Impair Defenses: Indicator Blocking** — `check_ip.php` interrogé toutes les secondes ; redirection silencieuse vers Google si l'IP est blacklistée par l'opérateur depuis le dashboard

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
| 15/04/2026 | Signalements | PHAROS, Clientify, INCIBE-CERT |
| 20/04/2026 | Signalement | cybermalveillance.gouv.fr |
| 22/04/2026 | Cloudflare | Restriction d'accès aux URLs + révélation hébergeur (Cloustrix / BROOKPLUS-LIMITED) |
| 22/04/2026 | Signalement | Cloustrix `abuse@cloustrix.com` |
| 22/04/2026 | Signalement | Action Fraud (UK) |
| 16/04/2026 | v2 – réponse | Takedown CDN |
| 20/04/2026 | INCIBE-CERT | Confirmation de prise en charge |

---

## 6. Indicateurs de compromission (IoC)

### Domaines

```
appurl[.]io
dfdsfsrt[.]cleverapps[.]io
paiementexpress[.]es
service-en-ligne-amendes-antai-gouv-fr[.]paiementexpress[.]es
app[.]clientify[.]com
clientify[.]net
```

### URLs

```
hxxps://appurl[.]io/wgMdQVVusR
hxxps://dfdsfsrt[.]cleverapps[.]io/service/payment-antai/amendes/index[.]php
hxxps://dfdsfsrt[.]cleverapps[.]io/service/payment-antai/amendes/details[.]php
hxxps://dfdsfsrt[.]cleverapps[.]io/service/payment-antai/amendes/card[.]php
hxxps://dfdsfsrt[.]cleverapps[.]io/service/payment-antai/amendes/Assets/php/config/func[.]php
hxxps://dfdsfsrt[.]cleverapps[.]io/service/payment-antai/amendes/Assets/js/js[.]js
hxxps://dfdsfsrt[.]cleverapps[.]io/service/payment-antai/amendes/Assets/js/stutes[.]js
hxxps://dfdsfsrt[.]cleverapps[.]io/service/payment-antai/amendes/status/update_status[.]php
hxxps://dfdsfsrt[.]cleverapps[.]io/service/payment-antai/amendes/status/check_ip[.]php
hxxps://appurl[.]io/jp-S8Zjien
hxxps://service-en-ligne-amendes-antai-gouv-fr[.]paiementexpress[.]es/net/index[.]php
hxxps://service-en-ligne-amendes-antai-gouv-fr[.]paiementexpress[.]es/net/details[.]php
hxxps://service-en-ligne-amendes-antai-gouv-fr[.]paiementexpress[.]es/net/card[.]php
hxxps://service-en-ligne-amendes-antai-gouv-fr[.]paiementexpress[.]es/net/Assets/php/config/func[.]php
hxxps://service-en-ligne-amendes-antai-gouv-fr[.]paiementexpress[.]es/net/Assets/js/js[.]js
hxxps://service-en-ligne-amendes-antai-gouv-fr[.]paiementexpress[.]es/net/Assets/js/stutes[.]js
hxxps://service-en-ligne-amendes-antai-gouv-fr[.]paiementexpress[.]es/net/status/update_status[.]php
hxxps://service-en-ligne-amendes-antai-gouv-fr[.]paiementexpress[.]es/net/status/check_ip[.]php
hxxps://service-en-ligne-amendes-antai-gouv-fr[.]paiementexpress[.]es/net/victims/{IP}[.]txt
hxxps://www[.]paiementexpress[.]es
```

### Emails

```
agonzalez@bilden[.]com[.]mx
alu[.]23130638@correo[.]itlalaguna[.]edu[.]mx
```

### Hashes SHA256 (pages HTML rendues côté client)

> Ces empreintes correspondent aux pages telles que reçues par le navigateur. Le code PHP exécuté côté serveur n'est pas inclus. Ils permettent d'identifier cette instance précise du kit ; toute modification du HTML, même mineure, produirait des empreintes différentes.

| Fichier | Arborescence v1 | Arborescence v2 | SHA256 |
|---|---|---|---|
| `index.php` | `/service/payment-antai/amendes/index.php` | `/net/index.php` | `00e0a3f0c9b435cfa0119f8853815127548beef5b3cd62454e49e4cb49027594` |
| `card.php` | `/service/payment-antai/amendes/card.php` | `/net/card.php` | `ae3cd7d937a32097294b63d0e5c49335b615f7f2b97eec94ed213cd80e245d76` |
| `js.js` | `/service/payment-antai/amendes/Assets/js/js.js` | `/net/Assets/js/js.js` | `be1ab9df8b052cb1306d9afe90088380530101323ac1a8e92cc918b9c1f420a6` |
| `stutes.js` | `/service/payment-antai/amendes/Assets/js/stutes.js` | `/net/Assets/js/stutes.js` | `eb036f1eaa0d35e643d9e2d1f43ed8a8e4f1d15ff58bdef88f7f90f240c23f0b` |

### Infrastructure

* Clever Cloud (`*.cleverapps.io`) — hébergement kit v1
* Cloudflare (reverse proxy / protection) — IPs mutualisées, non exploitables comme IoC. A prétendu restreindre l'accès aux URLs signalées tout en continuant à les servir — la "restriction" s'applique vraisemblablement uniquement à certaines requêtes automatisées, sans impact sur le trafic des victimes réelles. A révélé l'hébergeur réel (`BROOKPLUS-LIMITED`).
* **Cloustrix / BROOKPLUS-LIMITED** (GB) — hébergeur réel du kit v2, opérant vraisemblablement comme **hébergeur bulletproof**
  * Enregistrement légal : `BROOKPLUS LIMITED`, Companies House n° `16693924`, `35 Firs Avenue, London, N11 3NE`
  * Immatriculée le **4 septembre 2025** — société très récente
  * SIC `96090` ("Other service activities not elsewhere classified") — code fourre-tout masquant l'activité réelle
  * Fondée par un ressortissant **britannique** (adresse identique au siège social — pattern nominee director), contrôle transféré **27 jours après** la création à un ressortissant **italien** résidant en Toscane (né en février 1991) — schéma classique de shell company
  * Le nouveau contrôlant majoritaire (75%+, droits de vote + nomination des directeurs) n'a **pas encore passé la vérification d'identité Companies House** (due le 17/09/2026)
  * Site vitrine (`cloustrix.com`) sans aucun tunnel commercial ni formulaire de commande — présence légale uniquement
  * Datacenter Londres / Frankfurt / Pays-Bas, DDoS mitigation inclus — caractéristiques communes aux BPH
  * Contact abuse : `abuse@cloustrix.com`
* **Clientify, SL** (`app.clientify.com`) — plateforme CRM/email marketing utilisée comme plateforme d'envoi des emails frauduleux
  * NIF : B-04800249 — Reg. Mercantil Almería, T 1665, F 31, Hoja AL-43389
  * Contact abuse : `team@clientify.com`
  * DPO (enregistré AEPD) : `dpo@clientify.com`

---

## 7. Analyse technique

### 7.1 Chaîne d'attaque

1. Envoi email (via Clientify)
2. Redirection via raccourcisseur (`appurl.io`)
3. Challenge Cloudflare (anti-bot, type `managed`)
4. Page d'atterrissage — collecte d'identité (`index.php`)
5. Page de détails — affichage du montant (`details.php`)
6. Page de paiement — collecte bancaire (`card.php`)
7. Exfiltration backend (`func.php`)

---

### 7.2 Techniques d'évasion

#### Padding HTML et injection de liens légitimes

Le corps du message brut contient plusieurs dizaines de lignes vides ainsi que des URLs MSN anodines répétées. Cette technique vise deux objectifs : diluer la densité de termes suspects pour abaisser le score de risque des moteurs bayésiens, et introduire des domaines à bonne réputation dans le contenu analysé afin de tromper les filtres basés sur la réputation des URLs.

#### Encodage Quoted-Printable (RFC 2045)

Le message est encodé en Quoted-Printable, ce qui fragmente les chaînes de caractères sensibles (noms d'organismes, accents, ponctuation) en séquences hexadécimales (`=C3=A9`, `=E2=80=99`, etc.). Cette fragmentation rend l'extraction de signatures textuelles par les moteurs antispam moins fiable.

#### Cloaking et redirections dynamiques

Le lien initial pointe vers un raccourcisseur d'URL tiers (`appurl.io`) qui masque la destination finale. Le contenu servi peut varier selon les attributs de la requête (User-Agent, géolocalisation IP, présence de cookies), permettant de présenter un contenu neutre aux robots d'analyse et le kit de phishing aux victimes réelles.

#### Blocage IP actif en temps réel (`js.js` + `check_ip.php`)

Le script `js.js` interroge l'endpoint `./status/check_ip.php` **toutes les secondes**. Si la réponse contient `"blocked": true`, la victime est redirigée silencieusement vers `https://www.google.com`. Ce mécanisme permet à l'opérateur de blacklister depuis son dashboard les IPs des chercheurs, bots d'analyse ou équipes de takedown, sans que ceux-ci ne détectent le kit — ils voient simplement Google s'afficher.

```js
setInterval(() => {
    fetch('./status/check_ip.php', { cache: 'no-store' })
        .then(r => r.json())
        .then(d => {
            if (d.blocked === true) {
                window.location.replace("https://www.google.com");
            }
        });
}, 1000);
```

#### Protection CDN (Cloudflare — type `managed`)

Le site frauduleux est placé derrière un challenge Cloudflare de type `managed`, révélé par les paramètres `_cf_chl_opt` présents dans le code source de la page d'atterrissage. Cette couche remplit trois fonctions : masquer l'adresse IP réelle du serveur hébergeant le kit, bloquer les crawlers automatisés des équipes de threat intelligence, et conférer une apparence de légitimité via le certificat TLS associé au CDN.

---

### 7.3 Exfiltration

#### Architecture du tunnel de collecte

Le kit repose sur un tunnel en deux étapes distinctes, chacune soumettant ses données via `POST` vers le même script d'exfiltration backend (`./Assets/php/config/func.php`). Un champ caché (`<input type="hidden" name="card">`) permet au script de distinguer les soumissions de la page bancaire de celles de la page d'identité.

L'ensemble de l'infrastructure a migré entre la v1 et la v2, mais la structure du kit reste identique — seul le domaine d'hébergement change :

| Étape | v1 (`cleverapps.io`) | v2 (`paiementexpress.es`) |
|---|---|---|
| Page d'identité | `…/amendes/index.php` | `…/net/index.php` |
| Page de détails | `…/amendes/details.php` | `…/net/details.php` |
| Page de paiement | `…/amendes/card.php` | `…/net/card.php` |
| Exfiltration | `…/amendes/Assets/php/config/func.php` | `…/net/Assets/php/config/func.php` |
| Tracking | `…/amendes/status/update_status.php` | `…/net/status/update_status.php` |
| Blocage IP | `…/amendes/status/check_ip.php` | `…/net/status/check_ip.php` |

#### Étape 1 — Collecte d'identité (`index.php`)

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

Le formulaire contient également deux champs cachés : `cap` (probablement un token de session lié à l'IP, peuplé dynamiquement) et `details` (métadonnées de session injectées par `js.js`).

#### Étape 2 — Collecte bancaire (`card.php`)

| Champ | Masque jQuery | Remarque |
|---|---|---|
| Titulaire de la carte | Aucun | Texte libre |
| Numéro de carte | `0000 0000 0000 0000` | 16 chiffres — Visa / Mastercard |
| Date d'expiration | `00/00` | Format MM/AA |
| CVV | `0000` | **4 chiffres** — couvre aussi les cartes Amex |

L'utilisation d'un masque CVV à 4 chiffres indique un ciblage délibérément élargi aux porteurs de cartes American Express. Le footer reproduit fidèlement celui du portail officiel `amendes.gouv.fr` (DGFiP, Legifrance, Service-public.fr), renforçant l'illusion de légitimité.

#### Mécanisme d'exfiltration confirmé — stockage fichier exposé

L'analyse du comportement de `card.php` après soumission révèle le fonctionnement réel de `func.php` : les données collectées sont **écrites dans un fichier texte sur le serveur**, nommé d'après l'adresse IP de la victime, dans un répertoire `/victims/` accessible sans authentification.

Structure de l'URL d'accès aux données :

```
https://service-en-ligne-amendes-antai-gouv-fr.paiementexpress.es/net/victims/{IP_VICTIME}.txt?{TIMESTAMP_MS}
```

Le paramètre numérique suffixant l'URL (`?1777126717506`) est un **timestamp Unix en millisecondes**, vraisemblablement utilisé comme cache-buster pour forcer le rechargement du fichier côté dashboard opérateur.

Ce mécanisme présente plusieurs implications critiques :

- Le répertoire `/victims/` retourne un **403 Forbidden** — le listing est désactivé, empêchant l'énumération directe des victimes. Cependant, l'accès direct à un fichier dont l'URL est connue (`{IP}.txt`) est **public et sans authentification**, comme confirmé par test avec une IP et des données factices. Toute personne connaissant l'IP d'une victime peut lire ses données en clair.
- Les données de chaque victime (identité complète + coordonnées bancaires) sont **persistées en clair sur le serveur** plutôt qu'exfiltrées vers un canal externe — ce qui signifie qu'elles sont potentiellement récupérables par les autorités si le serveur est saisi
- L'opérateur accède aux données depuis son dashboard via ces URLs horodatées, ce qui est cohérent avec le mécanisme de tracking en temps réel (`stutes.js`)

> Endpoint d'accès aux données victimes (v2) :
> `hxxps://service-en-ligne-amendes-antai-gouv-fr[.]paiementexpress[.]es/net/victims/{IP}[.]txt`

#### Tracking en temps réel des victimes (`stutes.js`)

Le kit embarque un script de tracking qui envoie des pings toutes les 30 secondes vers `status/update_status.php`, signalant le statut `online` ou `offline` de la victime ainsi que la page consultée. Combiné au mécanisme de blocage IP de `js.js`, ce système implique l'existence d'un **dashboard d'administration** permettant à l'opérateur de surveiller et contrôler en temps réel chaque victime dans le tunnel.

> Endpoints de tracking :
> * v1 : `hxxps://dfdsfsrt[.]cleverapps[.]io/service/payment-antai/amendes/status/update_status[.]php`
> * v2 : `hxxps://service-en-ligne-amendes-antai-gouv-fr[.]paiementexpress[.]es/net/status/update_status[.]php`

---

## 8. Recommandations CERT

### Réponse immédiate

* Takedown coordonné auprès de l'hébergeur (Clever Cloud) et du CDN (Cloudflare).
* **Signalement PHAROS** (Police nationale / Gendarmerie nationale) — effectué. Référence : `FMXVFONYKVWA`, 15/04/2026 07:54.
* **Signalement cybermalveillance.gouv.fr** — effectué le 20/04/2026.
* Notification à l'ANTAI pour communication officielle auprès du public.
* **Signalement à Clientify, SL** — la plateforme CRM espagnole (`app.clientify.com`) est utilisée comme plateforme d'envoi des emails frauduleux. Son rôle se limite à ce stade à l'acheminement des messages initiaux vers les victimes ; l'hébergement du kit de phishing est masqué derrière Cloudflare en mode `managed` et ne peut être attribué à Clientify sans accès aux logs Cloudflare (réquisition judiciaire). Le signalement abuse a été effectué auprès de `team@clientify.com` et `dpo@clientify.com` avec les IoC et l'ID de campagne (`643018`).
* **Signalement à Cloustrix / BROOKPLUS-LIMITED (GB)** — hébergeur réel du kit v2, identifié grâce à la réponse de Cloudflare (Report ID `8d2a07ee4f9b24fc`). Société immatriculée le 4/09/2025, contrôle transféré 27 jours après la création à un ressortissant italien résidant en Toscane — schéma cohérent avec une shell company. Vérification d'identité du contrôlant majoritaire non encore effectuée auprès de Companies House (due le 17/09/2026). Signalement effectué à `abuse@cloustrix.com`.
* **Signalement à Action Fraud** (UK National Fraud & Cyber Reporting Centre) — compétent pour les sociétés immatriculées en England & Wales, avec accès direct à Companies House. Accepte les signalements de ressortissants étrangers dès lors que la société visée est immatriculée au Royaume-Uni. Signalement effectué via `actionfraud.police.uk`.

  > Note : Le NCSC UK limite ses signalements aux organisations et individus britanniques — non accessible pour un ressortissant français. Interpol disposait d'un portail de signalement cybercriminalité mais celui-ci était indisponible au moment de la rédaction de ce rapport.
* En cas d'absence de réaction de Clientify, escalade possible auprès de l'**AEPD** (Agencia Española de Protección de Datos) — le dossier d'identification (NIF B-04800249, Reg. Mercantil Almería T 1665 F 31 Hoja AL-43389) est suffisamment précis pour constituer un signalement formel.
* **Signalement à l'INCIBE-CERT** (Instituto Nacional de Ciberseguridad) — interlocuteur privilégié pour les domaines `.es` et les infrastructures espagnoles, avec des canaux directs auprès de Red.es pour les procédures de takedown. Signalement effectué. **Réponse reçue le 20/04/2026 : prise en charge confirmée**, analyse en cours selon leurs procédures internes.

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

L'analyse de bout en bout révèle un opérateur qui maîtrise les outils sans en avoir encore parfaitement rationalisé l'usage : la sophistication technique du kit (Cloudflare, tracking temps réel, **blocage IP actif**, tunnel de collecte structuré, support multilingue) contraste avec des erreurs opérationnelles visibles — adresses expéditrices non crédibles, v1 vraisemblablement déployée par inadvertance, recours à un hébergeur bulletproof (`Cloustrix / BROOKPLUS-LIMITED`) dont les indices de façade légale sont peu solides.

La rotation rapide vers une v2 après le takedown de la v1, combinée au recours probable à un hébergeur bulletproof, confirme que les délais de réponse actuels, bien qu'efficaces, ne suffisent pas à neutraliser durablement ce type d'acteur. Une approche préventive coordonnée — partage d'IoC en temps réel, notification proactive des hébergeurs et des CDN, communication publique de l'ANTAI, et coopération internationale (INCIBE-CERT, NCSC, Action Fraud) — reste la réponse la plus efficace face à des campagnes opportunistes de ce type.

---

*Rapport rédigé à des fins de documentation et de signalement. Tous les IoC sont défangés.*
