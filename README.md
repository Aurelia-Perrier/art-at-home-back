# Projet-12-art-at-home-back

## Présentation du projet

Avec l'apparition du covid, la vie en ligne s'est de plus en plus démocratisée. Les cours en ligne, les réunions en ligne et pourquoi pas l'art en ligne maintenant ? En effet, il est difficile pour les personnes reculées d'avoir accès aux expositions. C'est aussi un excellent moyen de sensibiliser les jeunes au monde artistique. C'est pour cela que la création d'une galerie d'art est aujourd'hui un excellent moyen d'ouvrir le monde de l'art au plus grand nombre.

## Description

Art@home a pour but de rendre accessible l'art (peinture, sculpture, photographie …etc.) depuis chez soi. Les artistes possèdent également une visibilité plus importante pendant une courte période en pouvant exposer leurs œuvres.

## Installation & Configuration du projet

### Installer les dépendences

``` composer install ```

### Configurer la base de données

- créer un **.env.local** à la racine du projet
- insérer la DATABASE_URL dans le .env.local : *DATABASE_URL="mysql://DATABASE_USERNAME:DATABASE_PASSWORD.0.0.1:3306/DATABASE_NAME?serverVersion=mariadb-10.3.25"*

### Création de la base de données

``` bin/console doctrine:database:create ```

``` bin/console doctrine:migrations:migrate ``` :  il peut y avoir une alerte dû aux tables crons mais cela n'empêche pas la création de la base de données

- importer le script SQL situé à la racine du projet dans le fichier **script.sql**.

