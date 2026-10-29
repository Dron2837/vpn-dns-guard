# Источники и политика списков

Снимок подготовлен 29 октября 2026 года. Списки ограничивают доступ к выбранным
сервисам. Они не подтверждают участие компаний в выявлении или блокировке VPN.

## Технический состав

Выпуск 0.1.0 включает 77 правил для корневых доменов с применением к их
поддоменам: 67 в группе `services`, 9 в `banks` и 1 в `gosuslugi`.
Количество правил не соответствует количеству сервисов: один сервис может
использовать несколько доменов. Фактический охват определяется файлами в `lists/`.

## Источники правил

- Каталог AdGuard: <https://github.com/AdguardTeam/HostlistsRegistry>
- Версия каталога на момент сбора: <https://adguardteam.github.io/HostlistsRegistry/assets/services.json>
  Выбраны точные идентификаторы `vk`, `mail_ru`, `ok`, `max`; `hbomax` не выбран.
- Домены Яндекса: <https://yandex.ru/blog/gamesfordevelopers/content-security-policy-i-novye-pravila-dostupa-k-khostam>
- Сетевые настройки Яндекса: <https://yandex.ru/support/yandex-360/business/admin/ru/network-settings>
- Домены Почты: <https://help.mail.ru/mail/account/moving/>
- Программа MAX, в том числе `*.oneme.ru` и `*.max.ru`:
  <https://bugbounty.standoff365.com/en-US/programs/max>
- Домены банков: <https://www.cbr.ru/banking_sector/credit/cowebsites/>
- ВТБ / ВТБ24: <https://www.vtb.ru/personal/online-servisy/vtb-online/instrukcii/>
- Т-Банк / бывший домен: <https://www.tbank.ru/invest/social/profile/T_InvestAPI/>
- ЕСИА: документация Минцифры на <https://sc.digital.gov.ru/>, адрес входа
  `esia.gosuslugi.ru` покрывается правилом `gosuslugi.ru`.

Адреса CDN и инфраструктуры могут меняться. Не включаются целиком общие облачные
IP-подсети и домены других организаций только из-за российского расположения.
Репутационные оценки и обвинения в передаче IP в правила не добавляются.
# Схема конфигурации AdGuard

Начальная конфигурация использует schema_version 34, соответствующую закреплённой
версии v0.107.79: https://github.com/AdguardTeam/AdGuardHome/blob/v0.107.79/internal/configmigrate/configmigrate.go

