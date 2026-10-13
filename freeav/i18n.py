"""Langue de l'interface graphique : francais (par defaut) ou anglais.

Les textes de gui.py restent ecrits en francais et passent par _() ; EN donne leur traduction.
La langue est lue une seule fois (au premier texte affiche) : un changement s'applique au
prochain demarrage de FreeAV."""

from . import privacy, updater

LANG_SETTING = "language"
LANGUAGES = {"fr": "Français", "en": "English"}

_lang: str | None = None  # langue lue au premier appel de _()


def current() -> str:
    """Langue enregistree dans ~/.freeav/config.json : "fr" ou "en" (tout le reste vaut "fr")."""
    value = updater.load_setting(LANG_SETTING, None, updater.CONFIG_FILE)
    return value if isinstance(value, str) and value in LANGUAGES else "fr"


def set_language(code: str) -> None:
    if code not in LANGUAGES:
        raise ValueError(f"Langue inconnue : {code}")
    updater.save_setting(LANG_SETTING, code, updater.CONFIG_FILE)


def translate(text: str, lang: str) -> str:
    if lang == "en":
        return EN.get(text, text)
    return text


def N_(text: str) -> str:
    """Marque un texte a traduire plus tard, a l'endroit ou il s'affiche (constantes de classe
    ou de module : _() y lirait la langue trop tot, avant le chargement des reglages)."""
    return text


def _(text: str) -> str:
    global _lang
    if _lang is None:
        _lang = current()
    return translate(text, _lang)


EN = {
    # Fenetre principale
    "FreeAV {version} - Antivirus gratuit": "FreeAV {version} - Free antivirus",
    "Pret.": "Ready.",
    "Installer FreeAV sur ce PC": "Install FreeAV on this PC",
    "Dossier a analyser :": "Folder to scan:",
    "Parcourir...": "Browse...",
    "Analyse rapide": "Quick scan",
    "Analyser ce dossier": "Scan this folder",
    "Arreter": "Stop",
    "clamd (avance)": "clamd (advanced)",
    "Quarantaine...": "Quarantine...",
    "Reparer mon PC...": "Repair my PC...",
    "Mettre a jour les signatures": "Update signatures",
    "Moteurs : signatures FreeAV": "Engines: FreeAV signatures",
    "+ 2e avis Microsoft Defender": "+ Microsoft Defender second opinion",
    "Protection en temps reel (Telechargements et Bureau)":
        "Real-time protection (Downloads and Desktop)",
    "Protection automatique...": "Automatic protection...",
    "Confidentialite...": "Privacy...",
    "Chercher les nouvelles versions": "Check for new versions",
    "Menace": "Threat",
    "Moteur": "Engine",
    "Fichier": "File",
    "Mettre en quarantaine la selection": "Quarantine selected",
    "Redemarrez FreeAV pour appliquer la nouvelle langue.":
        "Restart FreeAV to apply the new language.",
    "Chemin introuvable :\n{target}": "Path not found:\n{target}",
    "clamd injoignable : signatures uniquement.": "clamd is unreachable: using signatures only.",
    "Analyse approfondie par {engine}...": "In-depth scan by {engine}...",
    "L'analyse a echoue : {error}": "The scan failed: {error}",
    "Attention : {count} menace(s) trouvee(s) lors de la derniere analyse":
        "Warning: {count} threat(s) found in the last scan",
    "Protection FreeAV active (Telechargements, Bureau, cles USB) : "
    "gardez Microsoft Defender active":
        "FreeAV protection is on (Downloads, Desktop, USB drives): keep Microsoft Defender "
        "turned on",
    "Protection en temps reel desactivee : cochez-la ci-dessous":
        "Real-time protection is off: turn it on below",
    "ClamAV integre": "Built-in ClamAV",
    "Microsoft Defender": "Microsoft Defender",
    "+ ClamAV integre : non utilise en administrateur":
        "+ Built-in ClamAV: not used when running as administrator",
    "+ ClamAV integre : pret": "+ Built-in ClamAV: ready",
    "+ ClamAV integre : non installe": "+ Built-in ClamAV: not installed",
    "Mettre a jour ClamAV": "Update ClamAV",
    "Installer ClamAV (gratuit)": "Install ClamAV (free)",
    "Installer le moteur antivirus ClamAV (Cisco Talos, gratuit, licence GPL-2.0) ?\n\n"
    "FreeAV telecharge ClamAV depuis le site officiel de Cisco Talos, puis ses signatures "
    "officielles (environ 300 Mo). Les analyses deviennent plus completes et plus longues.\n\n"
    "Le module RAR de ClamAV, dont la licence n'est pas libre, n'est pas installe : "
    "l'interieur des archives RAR n'est pas analyse.":
        "Install the ClamAV antivirus engine (Cisco Talos, free, GPL-2.0 license)?\n\n"
        "FreeAV downloads ClamAV from the official Cisco Talos website, then its official "
        "signatures (about 300 MB). Scans become more thorough and take longer.\n\n"
        "ClamAV's RAR module, which is not under a free license, is not installed: the "
        "contents of RAR archives are not scanned.",
    "Signatures ClamAV a jour.": "ClamAV signatures are up to date.",
    "ClamAV est installe : il sera utilise a chaque analyse.":
        "ClamAV is installed: it will be used for every scan.",
    "ClamAV : {error}": "ClamAV: {error}",
    "Reglage non enregistre : {error}": "Setting not saved: {error}",
    "Mettre a jour FreeAV": "Update FreeAV",
    "Une nouvelle version de FreeAV est disponible (version {build}).":
        "A new version of FreeAV is available (version {build}).",
    "Installer la nouvelle version de FreeAV ?\n\nElle est telechargee depuis la page "
    "officielle de FreeAV sur GitHub et verifiee (empreinte SHA-256) avant de remplacer "
    "l'ancienne. FreeAV redemarre ensuite.":
        "Install the new version of FreeAV?\n\nIt is downloaded from FreeAV's official GitHub "
        "page and verified (SHA-256 checksum) before it replaces the current one. FreeAV then "
        "restarts.",
    "Attendez la fin de l'analyse en cours.": "Please wait for the current scan to finish.",
    "Mise a jour impossible : {error}": "Update failed: {error}",
    "FreeAV est a jour. Il va redemarrer.": "FreeAV is up to date and will now restart.",
    "Rouvrez FreeAV vous-meme ({error}).": "Please reopen FreeAV yourself ({error}).",
    "Installer FreeAV sur ce PC ? FreeAV va faire ces changements :\n- {changes}\n\n"
    "Rien d'autre n'est modifie. La protection en temps reel et l'analyse quotidienne restent "
    "a activer vous-meme.":
        "Install FreeAV on this PC? FreeAV will make these changes:\n- {changes}\n\n"
        "Nothing else is changed. You can turn on real-time protection and the daily scan "
        "yourself afterwards.",
    "FreeAV est installe :\n- {done}\n\nVous pouvez l'ouvrir depuis le menu Demarrer ou le "
    "Bureau.":
        "FreeAV is installed:\n- {done}\n\nYou can open it from the Start menu or the Desktop.",
    "Installation impossible : {error}": "Installation failed: {error}",
    "Protection en temps reel arretee.": "Real-time protection stopped.",
    "Aucun dossier Telechargements ou Bureau trouve.": "No Downloads or Desktop folder found.",
    "Protection en temps reel arretee : {error}": "Real-time protection stopped: {error}",
    "Protection en temps reel active : {folders}": "Real-time protection is on: {folders}",
    "{path} : {message}": "{path}: {message}",
    " (suspect)": " (suspicious)",
    "quarantaine": "quarantined",
    "FreeAV - protection en temps reel": "FreeAV - real-time protection",
    "Cle abuse.ch": "abuse.ch key",
    "MalwareBazaar demande une cle gratuite (Auth-Key).\n"
    "Creez-la sur https://auth.abuse.ch puis collez-la ici :":
        "MalwareBazaar requires a free key (Auth-Key).\n"
        "Create one at https://auth.abuse.ch, then paste it here:",
    "Telechargement des signatures MalwareBazaar...": "Downloading MalwareBazaar signatures...",
    "{added} nouvelles signatures, {total} au total.": "{added} new signatures, {total} in total.",
    "Analyse : {path}": "Scanning: {path}",
    "Aucune menace detectee.": "No threats found.",
    "{threats} menace(s), {suspects} suspect(s) a verifier.":
        "{threats} threat(s), {suspects} suspicious item(s) to check.",
    " {count} fichier(s) illisible(s).": " {count} file(s) could not be read.",
    "{scanned} fichiers analyses. {verdict}": "{scanned} files scanned. {verdict}",
    "Echec pour {path} :\n{error}": "Failed for {path}:\n{error}",
    "{moved} fichier(s) mis en quarantaine, {remaining} menace(s) restante(s).":
        "{moved} file(s) quarantined, {remaining} threat(s) remaining.",
    # Quarantaine
    "Quarantaine": "Quarantine",
    "Emplacement d'origine": "Original location",
    "Restaurer": "Restore",
    "Supprimer definitivement": "Delete permanently",
    # Reparer mon PC
    "Danger": "Danger",
    "Suspect": "Suspicious",
    "Info": "Info",
    "Outil": "Tool",
    "{status} - {title} : {message}": "{status} - {title}: {message}",
    "OK": "OK",
    "ECHEC": "FAILED",
    "Reparer mon PC": "Repair my PC",
    "Diagnostic en cours (rien n'est modifie)...": "Running diagnostics (nothing is changed)...",
    "Gravite": "Severity",
    "Categorie": "Category",
    "Probleme": "Problem",
    "Detail": "Details",
    "Reparer la selection": "Repair selected",
    "Annuler la derniere reparation": "Undo last repair",
    "Actualiser": "Refresh",
    "\nVous pouvez tout annuler avec « Annuler la derniere reparation ».":
        "\nYou can undo all of it with \"Undo last repair\".",
    "Erreur : {error}": "Error: {error}",
    " (admin)": " (admin required)",
    "{count} probleme(s) a examiner.": "{count} problem(s) to review.",
    "Aucun probleme important detecte.": "No significant problems found.",
    "Selectionnez un ou plusieurs problemes reparables dans la liste.":
        "Select one or more repairable problems in the list.",
    "- {title} : {fix}": "- {title}: {fix}",
    " (DEFINITIF)": " (PERMANENT)",
    "\n\nAttention : les actions marquees DEFINITIF ne pourront pas etre annulees (fichiers "
    "temporaires supprimes, outils Windows).":
        "\n\nWarning: actions marked PERMANENT cannot be undone (deleted temporary files, "
        "Windows tools).",
    "Les autres modifications sont sauvegardees et annulables.":
        "All other changes are backed up and can be undone.",
    "Toutes ces modifications sont sauvegardees et annulables.":
        "All these changes are backed up and can be undone.",
    "FreeAV va effectuer :\n{text}{warning}\n\n{undoable} Continuer ?":
        "FreeAV will do the following:\n{text}{warning}\n\n{undoable} Continue?",
    "Reparation en cours...": "Repairing...",
    "Aucune reparation a annuler.": "There are no repairs to undo.",
    "Annuler la derniere serie de reparations ?": "Undo the last set of repairs?",
    # Protection automatique
    "Protection automatique": "Automatic protection",
    "Chaque jour, FreeAV met a jour ses signatures (si une cle abuse.ch est enregistree), "
    "analyse vos Telechargements et votre Bureau, verifie les points sensibles du PC et vous "
    "previent en cas de probleme. Aucun droit administrateur n'est necessaire et tout se "
    "retire en un clic.":
        "Every day, FreeAV updates its signatures (if an abuse.ch key is saved), scans your "
        "Downloads and Desktop, checks the sensitive areas of your PC and alerts you if "
        "something is wrong. No administrator rights are needed, and everything can be removed "
        "in one click.",
    "Heure de l'analyse :": "Scan time:",
    "Proteger aussi en temps reel a chaque ouverture de session":
        "Also turn on real-time protection every time I sign in",
    "Activer": "Turn on",
    "Tout retirer": "Remove all",
    "Fermer": "Close",
    "{name} : {state}": "{name}: {state}",
    "active": "on",
    "inactive": "off",
    "Protection automatique activee :\n- {done}": "Automatic protection turned on:\n- {done}",
    "Retirer aussi ClamAV et ses signatures (environ 450 Mo) ?\n\nDossier : {folder}":
        "Also remove ClamAV and its signatures (about 450 MB)?\n\nFolder: {folder}",
    "ClamAV et ses signatures retires": "ClamAV and its signatures removed",
    "Rien a retirer.": "Nothing to remove.",
    # Confidentialite
    "FreeAV - Confidentialite": "FreeAV - Privacy",
    privacy.SUMMARY:
        "FreeAV has no account and sends neither your files nor usage data. Scans run on this "
        "PC, without the network.\n\n"
        "FreeAV connects to the Internet only to:\n"
        "- check for a new version of FreeAV (github.com), if the box below is checked, and "
        "download it when you ask;\n"
        "- download signatures, if you save an abuse.ch key (mb-api.abuse.ch);\n"
        "- install ClamAV when you ask (github.com/Cisco-Talos) and update its signatures "
        "(database.clamav.net).\n\n"
        "The Microsoft Defender second opinion scans the same folders. Defender follows its own "
        "Windows settings: it may send samples to Microsoft if cloud-delivered protection is "
        "turned on in Windows Security.\n\n"
        "You can change these choices at any time in the main window.",
    "Politique complete : {url}": "Full policy: {url}",
    "Chercher les nouvelles versions de FreeAV (github.com)":
        "Check for new FreeAV versions (github.com)",
    "2e avis Microsoft Defender pendant les analyses":
        "Microsoft Defender second opinion during scans",
    "Valider": "OK",
    "Reglages non enregistres : {error}": "Settings not saved: {error}",
    # Connexion (login_gui.py)
    "Connexion": "Sign in",
    "Verrouillé": "Locked",
    "Protéger l'accès": "Protect access",
    "Connexion...": "Sign-in...",
    "Verrouiller": "Lock",
    "Vérification": "Checking",
    "Enregistrement": "Saving",
    "Verr. Maj. activé": "Caps Lock is on",
    "Faible": "Weak",
    "Moyen": "Fair",
    "Bon": "Good",
    "Excellent": "Excellent",
    "12 caractères ou plus": "12 characters or more",
    "Trop court": "Too short",
    "Trop facile": "Too easy",
    "Antivirus gratuit et libre": "Free and open-source antivirus",
    "Protection en temps réel": "Real-time protection",
    "Téléchargements, Bureau, clés USB": "Downloads, Desktop, USB drives",
    "Analyse rapide en un clic": "One-click quick scan",
    "Signatures, YARA et ClamAV": "Signatures, YARA and ClamAV",
    "Connexion 100 % locale": "100% local sign-in",
    "Aucun compte en ligne": "No online account",
    "FreeAV {version}  ·  logiciel libre GPL-3.0": "FreeAV {version}  ·  GPL-3.0 free software",
    "ÉTAPE {current} SUR {total}": "STEP {current} OF {total}",
    "Impossible d'enregistrer : {error}": "Could not save: {error}",
    "Erreur inattendue : {error}": "Unexpected error: {error}",
    "Vous pouvez réessayer.": "You can try again.",
    "Trop d'essais. Réessayez dans {seconds} s.": "Too many attempts. Try again in {seconds} s.",
    "Bon retour": "Welcome back",
    "Entrez votre pseudo et votre mot de passe pour ouvrir FreeAV.":
        "Enter your nickname and password to open FreeAV.",
    "FreeAV est verrouillé": "FreeAV is locked",
    "La protection continue en arrière-plan. Connectez-vous pour rouvrir la fenêtre.":
        "Protection keeps running in the background. Sign in to reopen the window.",
    "Confirmez que c'est vous": "Confirm it's you",
    "Entrez votre mot de passe pour modifier la connexion à FreeAV.":
        "Enter your password to change how you sign in to FreeAV.",
    "Pseudo": "Nickname",
    "Mot de passe": "Password",
    "Mot de passe oublié ?": "Forgot password?",
    "Déverrouiller": "Unlock",
    "Continuer": "Continue",
    "Se connecter": "Sign in",
    "Annuler": "Cancel",
    "Quitter FreeAV": "Quit FreeAV",
    "Connexion locale : votre mot de passe et vos codes restent sur ce PC.":
        "Local sign-in: your password and codes stay on this PC.",
    "Entrez votre pseudo et votre mot de passe.": "Enter your nickname and password.",
    "Code de secours": "Recovery code",
    "Entrez l'un des codes de secours notés lors de la configuration. Chaque code ne sert "
    "qu'une fois.":
        "Enter one of the recovery codes you wrote down during setup. Each code works only once.",
    "Vérification en deux étapes": "Two-step verification",
    "Ouvrez Google Authenticator ou Microsoft Authenticator et entrez le code à 6 chiffres de "
    "FreeAV.":
        "Open Google Authenticator or Microsoft Authenticator and enter the 6-digit FreeAV code.",
    "Le code change toutes les 30 secondes.": "The code changes every 30 seconds.",
    "Retour": "Back",
    "Utiliser l'application": "Use the app",
    "Utiliser un code de secours": "Use a recovery code",
    "Entrez le code en entier.": "Enter the whole code.",
    "Il vous reste {count} code(s) de secours.": "You have {count} recovery code(s) left.",
    "Bienvenue, {name}": "Welcome, {name}",
    "Ouverture de FreeAV…": "Opening FreeAV…",
    "Code de secours utilisé : il vous en reste {count}. Créez-en de nouveaux depuis le bouton "
    "« Connexion » quand vous voulez.":
        "Recovery code used: you have {count} left. Create new ones from the \"Sign-in\" button "
        "whenever you like.",
    "Mot de passe oublié": "Forgot password",
    "Prouvez que c'est vous avec le code à 6 chiffres de votre application d'authentification "
    "ou avec un code de secours, puis choisissez un nouveau mot de passe.":
        "Prove it's you with the 6-digit code from your authenticator app or with a recovery "
        "code, then choose a new password.",
    "Prouvez que c'est vous avec l'un de vos codes de secours, puis choisissez un nouveau mot "
    "de passe.":
        "Prove it's you with one of your recovery codes, then choose a new password.",
    "Code OTP ou de secours": "OTP or recovery code",
    "Nouveau mot de passe": "New password",
    "Confirmez le mot de passe": "Confirm the password",
    "Changer le mot de passe": "Change password",
    "Retour à la connexion": "Back to sign-in",
    "Plus aucun code ?": "No codes left?",
    "Entrez votre pseudo et un code.": "Enter your nickname and a code.",
    "Les deux mots de passe ne sont pas identiques.": "The two passwords don't match.",
    "Mot de passe changé": "Password changed",
    "Connectez-vous maintenant avec votre nouveau mot de passe.":
        "Now sign in with your new password.",
    "Sans code de votre application ni code de secours, le mot de passe ne peut pas être "
    "changé : personne d'autre ne connaît vos codes, c'est ce qui protège FreeAV.\n\nLa "
    "connexion n'est qu'un verrou pour la fenêtre de FreeAV : pour la retirer, supprimez le "
    "fichier {path}. Vos réglages, la quarantaine et la protection ne sont pas touchés.":
        "Without a code from your app or a recovery code, the password can't be changed: no one "
        "else knows your codes, and that's what protects FreeAV.\n\nSign-in is only a lock on "
        "the FreeAV window: to remove it, delete the file {path}. Your settings, quarantine and "
        "protection are not affected.",
    "NOUVEAU": "NEW",
    "Protégez l'accès à FreeAV": "Protect access to FreeAV",
    "Sans votre pseudo et votre mot de passe, personne ne pourra ouvrir FreeAV, sortir un "
    "fichier de la quarantaine ni couper la protection depuis la fenêtre.":
        "Without your nickname and password, no one will be able to open FreeAV, restore a file "
        "from quarantine or turn off protection from the window.",
    "Un pseudo et un mot de passe à l'ouverture de FreeAV":
        "A nickname and password when FreeAV opens",
    "Un code à 6 chiffres sur votre téléphone (OTP), en option":
        "An optional 6-digit code on your phone (OTP)",
    "La protection en arrière-plan continue sans connexion":
        "Background protection keeps running without signing in",
    "Tout reste sur ce PC : aucun compte en ligne":
        "Everything stays on this PC: no online account",
    "Configurer": "Set up",
    "Plus tard": "Later",
    "Vous pourrez l'activer à tout moment avec le bouton « Connexion » de la fenêtre "
    "principale.":
        "You can turn it on at any time with the \"Sign-in\" button in the main window.",
    "Créez votre accès": "Create your sign-in",
    "Votre mot de passe n'est jamais enregistré en clair : FreeAV n'en garde qu'une empreinte.":
        "Your password is never stored as plain text: FreeAV only keeps a hash of it.",
    "Confirmation": "Confirm",
    "Code à usage unique (OTP)": "One-time code (OTP)",
    "RECOMMANDÉ": "RECOMMENDED",
    "Avec Google Authenticator ou Microsoft Authenticator":
        "With Google Authenticator or Microsoft Authenticator",
    "Scannez ce QR code": "Scan this QR code",
    "Dans votre application d'authentification, touchez « + », puis « Scanner un code QR ».":
        "In your authenticator app, tap \"+\", then \"Scan a QR code\".",
    "Pas de caméra ?": "No camera?",
    "Choisissez « Saisir une clé » et recopiez :": "Choose \"Enter a setup key\" and type:",
    "Copier la clé": "Copy the key",
    "Clé copiée.": "Key copied.",
    "Compte : {name} (FreeAV)\nType : basé sur l'heure":
        "Account: {name} (FreeAV)\nType: time-based",
    "Entrez le code affiché par l'application": "Enter the code shown by the app",
    "Vérifier": "Verify",
    "Entrez les 6 chiffres du code.": "Enter the 6 digits of the code.",
    "Code OTP activé : FreeAV le demandera à chaque connexion.":
        "OTP code turned on: FreeAV will ask for it every time you sign in.",
    "FreeAV est protégé": "FreeAV is protected",
    "À la prochaine ouverture, FreeAV demandera votre pseudo et votre mot de passe, puis le "
    "code de votre téléphone.":
        "Next time it opens, FreeAV will ask for your nickname and password, then the code from "
        "your phone.",
    "À la prochaine ouverture, FreeAV demandera votre pseudo et votre mot de passe.":
        "Next time it opens, FreeAV will ask for your nickname and password.",
    "Terminer": "Finish",
    "Notez vos codes de secours": "Write down your recovery codes",
    "Si vous oubliez votre mot de passe ou perdez votre téléphone, chaque code permet une fois "
    "de reprendre la main. Ils ne seront plus affichés.":
        "If you forget your password or lose your phone, each code lets you get back in once. "
        "They won't be shown again.",
    "Codes de secours FreeAV (chacun ne sert qu'une fois)":
        "FreeAV recovery codes (each one works only once)",
    "Codes copiés : collez-les dans un endroit sûr.": "Codes copied: paste them somewhere safe.",
    "Copier": "Copy",
    "Enregistrer…": "Save…",
    "J'ai mis ces codes en lieu sûr": "I've put these codes somewhere safe",
    "Enregistrer les codes de secours": "Save the recovery codes",
    "Texte": "Text",
    "Codes enregistrés dans {path}. Gardez ce fichier hors du PC (clé USB, papier...).":
        "Codes saved to {path}. Keep this file off the PC (USB drive, paper...).",
    "Connexion à FreeAV": "Signing in to FreeAV",
    "Connecté en tant que « {name} ». Ces réglages restent sur ce PC.":
        "Signed in as \"{name}\". These settings stay on this PC.",
    "Code OTP": "OTP code",
    "Activé": "On",
    "Désactivé": "Off",
    "Codes de secours": "Recovery codes",
    "{count} sur {total}": "{count} of {total}",
    "Le pseudo reste le même": "Your nickname stays the same",
    "Désactiver le code OTP": "Turn off the OTP code",
    "Le mot de passe suffira": "Your password will be enough",
    "Désactiver le code OTP ?": "Turn off the OTP code?",
    "FreeAV ne demandera plus que votre pseudo et votre mot de passe. Vous pourrez le réactiver.":
        "FreeAV will only ask for your nickname and password. You can turn it back on later.",
    "Désactiver": "Turn off",
    "Code OTP désactivé.": "OTP code turned off.",
    "Activer le code OTP": "Turn on the OTP code",
    "Google ou Microsoft Authenticator": "Google or Microsoft Authenticator",
    "Nouveaux codes de secours": "New recovery codes",
    "Les anciens ne marcheront plus": "The old ones will stop working",
    "Remplacer vos codes de secours ?": "Replace your recovery codes?",
    "Vous recevrez 8 nouveaux codes. Les anciens ne marcheront plus.":
        "You'll get 8 new codes. The old ones will stop working.",
    "Remplacer": "Replace",
    "Nouveaux codes de secours enregistrés.": "New recovery codes saved.",
    "Retirer la connexion": "Remove sign-in",
    "FreeAV s'ouvrira sans mot de passe": "FreeAV will open without a password",
    "Retirer la connexion ?": "Remove sign-in?",
    "FreeAV s'ouvrira de nouveau sans pseudo ni mot de passe. La protection n'est pas touchée.":
        "FreeAV will open again without a nickname or password. Protection is not affected.",
    "Retirer": "Remove",
    "Connexion retirée": "Sign-in removed",
    "FreeAV s'ouvrira de nouveau sans mot de passe. Vous pouvez la réactiver à tout moment.":
        "FreeAV will open without a password again. You can turn sign-in back on at any time.",
    "Choisissez un mot de passe d'au moins 12 caractères, par exemple trois mots séparés par "
    "des tirets.":
        "Choose a password of at least 12 characters, for example three words separated by "
        "hyphens.",
    "Enregistrer": "Save",
    "Mot de passe changé.": "Password changed.",
    # Messages de login.py (login.Message, traduits par login_gui.tr)
    "Pseudo ou mot de passe incorrect.": "Incorrect nickname or password.",
    "Code incorrect ou expiré.": "Incorrect or expired code.",
    "Entrez le code de votre application d'authentification.":
        "Enter the code from your authenticator app.",
    "Trop d'essais. Réessayez dans {duration}.": "Too many attempts. Try again in {duration}.",
    "{count} secondes": "{count} seconds",
    "{count} minutes": "{count} minutes",
    "Le mot de passe doit faire de {min} à {max} caractères.":
        "The password must be {min} to {max} characters long.",
    "Le mot de passe ne doit pas être votre pseudo.": "The password must not be your nickname.",
    "Ce mot de passe est trop facile à deviner.": "This password is too easy to guess.",
    "Base de la connexion illisible ou occupée ({error}). Si DBeaver l'utilise, fermez-le puis "
    "réessayez. Pour retirer la connexion, supprimez {path}.":
        "The sign-in database can't be read or is busy ({error}). If DBeaver is using it, close "
        "it and try again. To remove sign-in, delete {path}.",
    "Le pseudo doit faire 3 à 32 caractères : lettres, chiffres, point, tiret ou _.":
        "The nickname must be 3 to 32 characters: letters, digits, dot, hyphen or _.",
    "La connexion n'est pas activée.": "Sign-in is not turned on.",
    "Pseudo ou code incorrect.": "Incorrect nickname or code.",
    "Code incorrect. Vérifiez que l'heure du téléphone est juste.":
        "Incorrect code. Check that your phone's clock is right.",
}
