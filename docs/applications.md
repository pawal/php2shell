# Additional PHP application coverage

Reviewed 2026-10-22. This catalogue update adds 50 applications beyond
Roundcube and the previously recognised CMS/application names. The set
covers common deployment categories; it is not a statistical ranking of
the fifty most popular PHP products. Frameworks remain a separate catalogue.

Selection was informed by the [W3Techs CMS survey](https://w3techs.com/technologies/overview/content_management)
and [WhatCMS technology categories](https://whatcms.org/Technologies).
PHP implementation and signal details were checked against the linked
project sources or the vendors' own documentation. These catalogue rules
are independently written, not copied from a third-party scanner database.

| Category | New applications |
|---|---|
| Forums | 6 |
| CMS | 1 |
| Wikis | 5 |
| Database administration | 3 |
| Files and collaboration | 4 |
| Help desks | 4 |
| CRM and business | 6 |
| Learning | 4 |
| Analytics and publishing | 7 |
| Galleries | 4 |
| Business tools | 6 |

## Coverage and sources

All entries accept explicit application names in generator or identity
headers. The table lists the additional researched signals or a generator
that the linked template actually emits. A generator or application version
MUST NOT become a PHP version.

| Application | Category | Researched signal | Primary source |
|---|---|---|---|
| XenForo | Forums | cookie `xf_session`; cookie `xf_csrf`; cookie `xf_user` | [Source](https://xenforo.com/community/help/cookies/) |
| Invision Community | Forums | cookie `ips4_IPSSessionFront`; cookie `ips4_member_id`; cookie `ips4_login_key` | [Source](https://invisioncommunity.com/cookies/) |
| MyBB | Forums | cookie `mybbuser` | [Source](https://raw.githubusercontent.com/mybb/mybb/feature/inc/class_session.php) |
| Simple Machines Forum | Forums | SMF logo ID and alt text | [Source](https://raw.githubusercontent.com/SimpleMachines/SMF/release-2.1/Themes/default/index.template.php) |
| MODX | CMS | HTTP 5xx diagnostic identifier `MODX\Revolution\` | [Source](https://raw.githubusercontent.com/modxcms/revolution/3.x/core/src/Revolution/modX.php) |
| Flarum | Forums | cookie `flarum_remember` | [Source](https://raw.githubusercontent.com/flarum/framework/HEAD/framework/core/src/Http/CookieFactory.php) |
| bbPress | Forums | CSS `css/bbpress.css` | [Source](https://raw.githubusercontent.com/bbpress/bbPress/trunk/src/templates/default/bbpress-functions.php) |
| DokuWiki | Wikis | generator meta tag | [Source](https://raw.githubusercontent.com/dokuwiki/dokuwiki/master/inc/template.php) |
| PmWiki | Wikis | CSS `pmwiki-core.css` | [Source](https://www.pmwiki.org/wiki/PmWiki/Requirements) |
| Tiki Wiki | Wikis | generator meta tag | [Source](https://gitlab.com/tikiwiki/tiki/-/raw/master/templates/header.tpl) |
| WackoWiki | Wikis | CSS `css/wacko.css` | [Source](https://raw.githubusercontent.com/WackoWiki/wackowiki/HEAD/src/theme/_common/_header.tpl) |
| BookStack | Wikis | cookie `bookstack_session` | [Source](https://raw.githubusercontent.com/BookStackApp/BookStack/HEAD/app/Config/session.php) |
| phpMyAdmin | Database administration | cookie `phpMyAdmin` | [Source](https://raw.githubusercontent.com/phpmyadmin/phpmyadmin/HEAD/src/Session.php) |
| Adminer | Database administration | cookie `adminer_sid` | [Source](https://raw.githubusercontent.com/vrana/adminer/master/adminer/include/bootstrap.inc.php) |
| phpPgAdmin | Database administration | cookie `PPA_ID` | [Source](https://raw.githubusercontent.com/phppgadmin/phppgadmin/master/libraries/lib.inc.php) |
| Nextcloud | Files and collaboration | cookie `nc_sameSiteCookielax`; cookie `nc_sameSiteCookiestrict`; cookie `__Host-nc_sameSiteCookielax`; cookie `__Host-nc_sameSiteCookiestrict` | [Source](https://raw.githubusercontent.com/nextcloud/server/master/lib/private/AppFramework/Http/Request.php) |
| ownCloud | Files and collaboration | branded link within the application footer | [Source](https://raw.githubusercontent.com/owncloud/core/master/core/templates/layout.guest.php) |
| FileGator | Files and collaboration | HTTP 5xx diagnostic identifier `Filegator\` | [Source](https://raw.githubusercontent.com/filegator/filegator/master/backend/Services/Session/Adapters/SessionStorage.php) |
| Tiny File Manager | Files and collaboration | login field pair inside one form | [Source](https://raw.githubusercontent.com/prasathmani/tinyfilemanager/master/tinyfilemanager.php) |
| osTicket | Help desks | cookie `OSTSESSID` | [Source](https://raw.githubusercontent.com/osTicket/osTicket/develop/include/class.ostsession.php) |
| GLPI | Help desks | GLPI theme and request-ID attributes on the same HTML element | [Source](https://raw.githubusercontent.com/glpi-project/glpi/main/templates/layout/parts/head.html.twig) |
| FreeScout | Help desks | branded link within the application footer | [Source](https://raw.githubusercontent.com/freescout-helpdesk/freescout/dist/resources/views/layouts/app.blade.php) |
| UVdesk | Help desks | script `bundles/uvdeskcoreframework/js/_dropdown.js`, `bundles/uvdeskcoreframework/js/viewer.js` | [Source](https://raw.githubusercontent.com/uvdesk/core-framework/master/Resources/views/Templates/layout.html.twig) |
| Dolibarr | CRM and business | cookie `^DOLSESSID_[0-9a-f]{40}$` | [Source](https://raw.githubusercontent.com/Dolibarr/dolibarr/develop/htdocs/main.inc.php) |
| EspoCRM | CRM and business | HTTP 5xx diagnostic identifier `Espo\` | [Source](https://raw.githubusercontent.com/espocrm/espocrm/master/application/Espo/Core/Utils/Config/ConfigFileManager.php) |
| SuiteCRM | CRM and business | script `themes/SuiteP/js/jscolor.js`, `cache/include/javascript/sugar_field_grp.js` | [Source](https://raw.githubusercontent.com/salesagility/SuiteCRM/master/themes/SuiteP/tpls/_head.tpl) |
| Vtiger | CRM and business | script `include/js/vtlib.js`, `include/js/general.js` | [Source](https://raw.githubusercontent.com/vtiger-crm/vtigercrm/master/Smarty/templates/Header.tpl) |
| CiviCRM | CRM and business | HTTP 5xx diagnostic identifier `CRM_Core_Session` | [Source](https://raw.githubusercontent.com/civicrm/civicrm-core/master/CRM/Core/Session.php) |
| Mautic | CRM and business | HTTP 5xx diagnostic identifier `Mautic\` | [Source](https://raw.githubusercontent.com/mautic/mautic/5.x/app/config/config.php) |
| Moodle | Learning | cookie `MoodleSession` | [Source](https://raw.githubusercontent.com/moodle/moodle/MOODLE_405_STABLE/lib/classes/session/manager.php) |
| Chamilo | Learning | generator meta tag | [Source](https://raw.githubusercontent.com/chamilo/chamilo-lms/1.11.x/main/template/default/layout/head.tpl) |
| ILIAS | Learning | cookie `ilClientId` | [Source](https://raw.githubusercontent.com/ILIAS-eLearning/ILIAS/HEAD/components/ILIAS/Init/classes/class.ilInitialisation.php) |
| Mahara | Learning | generator meta tag | [Source](https://raw.githubusercontent.com/MaharaProject/mahara/master/htdocs/theme/raw/templates/header/head.tpl) |
| LimeSurvey | Analytics and publishing | generator meta tag | [Source](https://raw.githubusercontent.com/LimeSurvey/LimeSurvey/master/themes/survey/vanilla/views/subviews/header/head.twig) |
| Matomo | Analytics and publishing | cookie `MATOMO_SESSID` | [Source](https://raw.githubusercontent.com/matomo-org/matomo/5.x-dev/core/Session.php) |
| YOURLS | Analytics and publishing | generator meta tag | [Source](https://raw.githubusercontent.com/YOURLS/YOURLS/master/includes/functions-html.php) |
| wallabag | Analytics and publishing | cookie `wllbg_trusted_computer` | [Source](https://raw.githubusercontent.com/wallabag/wallabag/master/app/config/config.yml) |
| FreshRSS | Analytics and publishing | cookie `FreshRSS` | [Source](https://raw.githubusercontent.com/FreshRSS/FreshRSS/edge/app/FreshRSS.php) |
| Tiny Tiny RSS | Analytics and publishing | script `js/tt-rss.js`, `lib/dojo/tt-rss-layer.js` | [Source](https://raw.githubusercontent.com/tt-rss/tt-rss/master/index.php) |
| Shaarli | Analytics and publishing | CSS `css/shaarli.min.css` | [Source](https://raw.githubusercontent.com/shaarli/Shaarli/master/tpl/default/includes.html) |
| Piwigo | Galleries | generator meta tag | [Source](https://raw.githubusercontent.com/Piwigo/Piwigo/master/themes/default/template/header.tpl) |
| Coppermine | Galleries | CSS `css/coppermine.css` | [Source](https://raw.githubusercontent.com/coppermine-gallery/cpg1.6.x/master/include/themes.inc.php) |
| Zenphoto | Galleries | script `js/zp_general.js` | [Source](https://raw.githubusercontent.com/zenphoto/zenphoto/master/zp-core/template-functions/template-functions-general.php) |
| Lychee | Galleries | cookie `lychee_session` | [Source](https://raw.githubusercontent.com/LycheeOrg/Lychee/master/config/session.php) |
| Invoice Ninja | Business tools | cookie `invoice_ninja_session` | [Source](https://raw.githubusercontent.com/invoiceninja/invoiceninja/v5-stable/config/session.php) |
| InvoicePlane | Business tools | cookie `ip_session`; cookie `ip_csrf_cookie` | [Source](https://raw.githubusercontent.com/InvoicePlane/InvoicePlane/development/application/config/config.php) |
| Akaunting | Business tools | cookie `akaunting_session` | [Source](https://raw.githubusercontent.com/akaunting/akaunting/master/config/session.php) |
| Snipe-IT | Business tools | cookie `snipeitv6_session` | [Source](https://raw.githubusercontent.com/grokability/snipe-it/master/config/session.php) |
| Kanboard | Business tools | cookie `KB_SID` | [Source](https://raw.githubusercontent.com/kanboard/kanboard/main/app/Core/Session/SessionManager.php) |
| phpList | Business tools | paired branded icon links | [Source](https://raw.githubusercontent.com/phpList/phplist3/main/public_html/lists/admin/ui/default/header.inc) |

## Conditions and limits

- Cookie names are low-confidence hints. Names, prefixes and application
  names are configurable. MyBB, Flarum and wallabag cookies may appear only
  in authenticated or remembered-session contexts; their absence says nothing.
- Nextcloud protected-cookie variants are recognised explicitly. Generic
  ownCloud/Nextcloud session IDs are not used to distinguish the products.
- Invoice Ninja and Akaunting cookie names are derived from the shipped
  application-name examples and session configuration. Customized names
  are not guessed. Moodle recognition uses its default cookie name.
- Dolibarr recognition requires its named prefix and a 40-character SHA-1
  suffix. An arbitrary similarly prefixed cookie is not sufficient.
- Assets and branding can be copied, cached or reused. They are component
  evidence with low confidence, not proof that the requested page executes PHP.
- Generic JavaScript/CSS names, product mentions, titles and ordinary article
  links do not identify an application. Required markup attributes must
  occur together on the intended element or within the designated container.
- MODX, FileGator, EspoCRM, CiviCRM and Mautic currently have diagnostic or
  explicit-identity coverage only. Diagnostics require an existing HTTP 5xx
  response with an exception/trace context. The checker induces no errors
  and requests no debug endpoints.
- These are application-family rules, not guarantees across every version,
  skin or installation. Some sources intentionally cover older deployed
  themes. Challenges, branding changes, disabled diagnostics and custom
  cookies can hide all signals.

Additional references establish configurable defaults or emitted branding:

- Flarum: [reference](https://raw.githubusercontent.com/flarum/framework/HEAD/framework/core/src/Http/Rememberer.php).
- ownCloud: [reference](https://raw.githubusercontent.com/owncloud/core/master/lib/private/legacy/defaults.php).
- FreeScout: [reference](https://raw.githubusercontent.com/freescout-helpdesk/freescout/dist/config/app.php).
- Dolibarr: [reference](https://raw.githubusercontent.com/Dolibarr/dolibarr/develop/htdocs/core/lib/functions.lib.php).
- Invoice Ninja: [reference](https://raw.githubusercontent.com/invoiceninja/invoiceninja/v5-stable/.env.example).
- Akaunting: [reference](https://raw.githubusercontent.com/akaunting/akaunting/master/.env.example).

## Verification

Each of the fifty entries has a separate synthetic response fixture derived
from the cited producers or documentation. Tests verify the detected name,
provenance, confidence, verdict integration and PHP-version separation.
Negative cases cover generic cookies, lookalikes, invalid hash suffixes,
ordinary article links, comments, unrelated assets, split attributes and
unrelated login forms. Request IDs, cookie values and trace contents are
not copied into fingerprint evidence.

The catalogue consumes existing bounded responses. It adds no target
requests, login attempts or authenticated inspection. These fixtures are
not live acceptance tests against fifty deployed applications. See
[fingerprints.md](fingerprints.md) for framework and Roundcube coverage, and
[detection.md](detection.md) for discovery and blocked inspection.

Validation on 2026-10-22: `make test`, `make build` and `make test-lab`
passed. The PHP lab checks patched, unpatched and hardened PHP plus a static
server; application-family coverage is established by the separate fixtures.
