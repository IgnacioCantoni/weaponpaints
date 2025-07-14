<?php

// Choose your translate file name located in translation/filename.json
// You can add your own translation.
$Website_Translate = "es";

// You can choose your own theme color
// false/empty - will use the default color.
// any html acceptable color - will display that color: "#5D3FD3".
// true - this will get a random color.
$Website_MainColor = "#4f75ff";

// Enable this if you want categories else it will display all weapons.
$Website_UseCategories = true;

// Enable this if you want 3d preview of skins.
// note: disabling this will disable stickers custom placement too (not an option yet, future feature).
$Website_UseThreejs = true;

// Exclusive team weapons will only be able to set to their team.
// for example m4a4 skins will only be equipped to ct team, skin will not be visible on t side.
$Website_TeamOnlyWeapons = true;

// Select which settings you want in the menu.
$Website_Settings = [
    "language" => true,  // user can select his own language.
    "theme" => true      // user can change his own color theme.
];

// Write here your steam api key, get one from here: https://steamcommunity.com/dev/apikey.
$SteamAPI_KEY = "DAB3A983EF5A35239C8A1C8AB9FE8011";

$DatabaseInfo = [
    "host" => "shuttle.proxy.rlwy.net",
    "database" => "railway",
    "username" => "root",
    "password" => "vPRKYwpxLAHlzmXXZzZMfyzLDTqFbnUM",
    "port" => "23851"
];
