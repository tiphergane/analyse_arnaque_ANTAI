# Analyse d'une campagne de phishing usurpant l'identité de l'ANTAI

> **Contexte** : Ce rapport documente l'analyse technique d'un courriel frauduleux reçu par une victime ciblée, se faisant passer pour une notification officielle de l'Agence Nationale de Traitement Automatisé des Infractions (ANTAI).

---

## 1. Point d'entrée — Le courriel frauduleux

### Contenu du message

```
De : Règlement en attente ANTAI <agonzalez@bilden.com.mx>
Date : mar. 14 avr. 2026 à 13:14
Objet : Règlement en attente
À : <adresse_de_cible@gmail.com>

Bonjour,

Nous vous informons qu'une nouvelle information a été déposée dans votre espace personnel.
Cette action est obligatoire et doit être effectuée dans les délais impartis.
Nous vous invitons à vous y connecter sans tarder afin de régulariser votre situation.

Accéder à votre espace en ligne

Cordialement,
```

### Indicateurs de compromission immédiats

Le message présente plusieurs signaux d'alerte évidents :

- **Domaine expéditeur** : `bilden.com.mx` — adresse mexicaine sans aucun lien avec l'ANTAI ni les services de l'État français.
- **Contenu vague** : aucune référence d'infraction, aucun montant, aucun numéro de dossier — typique d'un hameçon généraliste.
- **Lien piégé** : le CTA renvoie vers un raccourcisseur d'URL tiers (`appurl.io`), masquant la destination réelle.

> URL de redirection : `https://appurl.io/wgMdQVVusR`

---

## 2. Évasion des filtres antispam

### Technique utilisée : encodage Quoted-Printable

L'e-mail brut révèle une technique d'obfuscation classique pour contourner les filtres antispam. Le corps du message est encodé en **Quoted-Printable** (RFC 2045), ce qui fragmente les chaînes de caractères sensibles :

```
R=C3=A8glement en attente ANTAI <agonzalez@bilden.com.mx>
Nous vous informons qu=E2=80=99une nouvelle information a =C3=A9t=C3=A9 d=
=C3=A9pos=C3=A9e dans votre espace personnel.
```

### Rembourrage par lignes vides

Le corps du message contient des dizaines de lignes vides ainsi que des URLs MSN anodines répétées en fin de message. Cette technique vise à diluer la densité des termes suspects et à améliorer le score de réputation auprès des moteurs d'analyse bayésienne.

### Second e-mail plus agressif

Une variante du message (probablement envoyée en relance) adopte un ton nettement plus pressant, avec une escalade artificielle du montant :

- Montant initial affiché : **135 €**
- Montant « réévalué » affiché : **295,99 €** (justifié par un prétendu retard)
- Menace de majoration à **750 €** sous 72 heures
- Promesse de remboursement de **160,99 €** en cas de paiement immédiat

Ces éléments constituent des techniques classiques de manipulation psychologique basées sur l'urgence et la peur.

---

## 3. Infrastructure technique — Le site façade

### Première couche : protection Cloudflare

Le clic sur le lien raccourci redirige vers un challenge Cloudflare (type `managed`). Le code source de la page révèle les paramètres Cloudflare habituels (`_cf_chl_opt`, `cType: 'managed'`, `cZone: 'appurl.io'`).

```html
<!DOCTYPE html>
<html lang="en-US">
  <head>
    <title>Just a moment...</title>
    ...
  </head>
  <body>
    <script>
      window._cf_chl_opt = {
        cvId: '3',
        cZone: 'appurl.io',
        cType: 'managed',
        cRay: '9ec48991ae5a06b2',
        ...
      };
    </script>
  </body>
</html>
```

**Analyse** : Les attaquants placent délibérément le site frauduleux derrière Cloudflare afin de :
1. Masquer l'adresse IP réelle du serveur hébergeant le kit de phishing.
2. Compliquer les tentatives de signalement et de démantèlement.
3. Conférer une apparence de légitimité au domaine (certificat TLS, infrastructure reconnue).

---

## 4. Le kit de phishing — Collecte de données personnelles

### Page d'atterrissage (`index.php`)

Hébergée sur `dfdsfsrt.cleverapps.io`, la page imite visuellement le portail officiel de paiement des amendes (logo ANTAI, charte graphique, footer DGFiP). Elle affiche le formulaire de collecte suivant :

| Champ          | Type       |
|----------------|------------|
| Nom            | Texte      |
| Prénom         | Texte      |
| Date de naissance | Texte (masque JJ/MM/AAAA) |
| Adresse e-mail | Email      |
| Numéro de téléphone | Numérique |
| Adresse postale | Texte     |
| Ville          | Texte      |
| Code postal    | Texte      |

Le formulaire soumet les données via `POST` vers `./Assets/php/config/func.php` — le script d'exfiltration côté serveur.

À noter : le site inclut un sélecteur de langue (FR, EN, DE, NL, IT, ES), ce qui indique une campagne multi-pays probablement mutualisée.

---

## 5. Tracking en temps réel des victimes

### Script de suivi (`stutes.js`)

Le kit embarque un script JavaScript de *live tracking* qui notifie l'attaquant en temps réel de la présence d'une victime sur le site :

```js
let path_page = window.location.href;

function updateStatus(status) {
    fetch('./status/update_status.php', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ status, page: `${path_page}` })
    });
}

updateStatus('online');

window.addEventListener('beforeunload', () => {
    updateStatus('offline');
});

setInterval(() => {
    updateStatus('online');
}, 30000);
```

Ce script envoie périodiquement un ping toutes les 30 secondes vers le dashboard de l'attaquant, indiquant si la victime est `online` ou `offline` ainsi que la page consultée. Cela suggère l'existence d'une **interface d'administration** permettant une interaction manuelle en temps réel avec les victimes.

> Endpoint de tracking : `https://dfdsfsrt.cleverapps.io/service/payment-antai/amendes/status/update_status.php`

---

## 6. Cartographie de l'infrastructure

La chaîne d'attaque complète se décompose comme suit :

```
Courriel / SMS frauduleux
        ↓
  appurl.io (raccourcisseur d'URL)
        ↓
  Challenge Cloudflare (protection anti-démantèlement)
        ↓
  cleverapps.io — index.php (page façade ANTAI)
        ↓
  details.php (affichage du montant et du formulaire)
        ↓
  Formulaire d'identité (collecte PII)
        ↓
  func.php (exfiltration des données)
        ↓
  status/update_status.php (tracking live de la victime)
        ↓
  Page CB (étape suivante probable — collecte des données bancaires)
```

---

## 7. Signalement

Un signalement a été effectué auprès de la plateforme **PHAROS** (Police nationale / Gendarmerie nationale). Référence obtenue :

```
Type : Escroquerie
Référence : FMXVFONYKVWA
Date : 15/04/2026 07:54
```

> Pour toute information complémentaire, il est possible d'effectuer un nouveau signalement en mentionnant cette référence dans le commentaire.

Un signalement complémentaire à l'hébergeur Clever Cloud (`cleverapps.io`) est également recommandé pour demande de suspension du compte.

---

## 8. Conclusion

L'analyse révèle un **kit de phishing clé en main**, relativement bien construit, ciblant les usagers de l'ANTAI. Malgré un courriel d'entrée au contenu générique et peu soigné — qui pouvait initialement laisser supposer une attaque de faible sophistication —, l'infrastructure sous-jacente témoigne d'un niveau d'organisation supérieur à la moyenne :

- Utilisation de Cloudflare pour masquer et protéger le serveur malveillant.
- Imitation visuelle fidèle du portail ANTAI officiel.
- Interface de suivi en temps réel des victimes, suggérant un **dashboard d'administration** et une possible intervention manuelle de l'opérateur.
- Support multilingue indiquant une campagne potentiellement à portée européenne.

L'ensemble de ces éléments est cohérent avec l'utilisation d'un **phishing-as-a-service** (PhaaS) ou d'un kit revendu sur des forums spécialisés, exploité par un acteur cherchant à monter en gamme dans ses pratiques frauduleuses.

---

## 9. Indicateurs de Compromission (IoC)

| Type         | Valeur                                                                 |
|--------------|------------------------------------------------------------------------|
| E-mail       | `agonzalez@bilden[.]com[.]mx`                                          |
| URL          | `https://appurl[.]io/wgMdQVVusR`                                       |
| URL backend  | `https://dfdsfsrt[.]cleverapps[.]io/service/payment-antai/amendes/status/update_status[.]php` |
| URL campagne | `https://app[.]clientify[.]com/email-marketing/plus/campaigns/view/body/643018/1776086009/` |
| URL market   | `www.paiementexpress`                                                      |
| URL v2       | `service-en-ligne-amendes-antai-gouv-fr.paiementexpress.es`            |
