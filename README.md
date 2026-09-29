# Домашнее задание: Практика с SELinux

## 1. Стенд

| Параметр | Значение |
|---|---|
| Гипервизор | Proxmox VE |
| ns01 | Rocky Linux 10, SELinux **Enforcing** |
| client | Ubuntu 24.04 |
| DNS-сервер | BIND 9.16+ (named), зоны dns.lab / ddns.lab / newdns.lab, TSIG-ключ `zonetransfer.key` |
| Сеть | вместо вагрантовской 192.168.50.0/24 используется реальная 192.168.1.0/24 |

Стенд развёрнут адаптированным плейбуком `stand/provisioning/playbook-adapted.yml` (inventory: `stand/provisioning/inventory.ini`) из репозитория `Nickmob/vagrant_selinux_dns_problems`. Правки под текущий BIND: убран устаревший `dnssec-enable`, `dnssec-validation auto`, ddns-зоны кладутся явно в `/etc/named/dynamic/`.

## 2. Задание 1. Nginx на нестандартном порту 4881 — 3 способа

Состояние до: `getenforce` = **Enforcing**, firewalld остановлен, nginx слушает 4881. Попытка старта падает:
`nginx: [emerg] bind() to 0.0.0.0:4881 failed (13: Permission denied)`.

Диагностика (одинакова для всех способов):

```
# grep 4881 /var/log/audit/audit.log | audit2why
type=AVC msg=audit(...): avc: denied { name_bind } for pid=2369 comm="nginx"
  src=4881 scontext=system_u:system_r:httpd_t:s0
  tcontext=system_u:object_r:unreserved_port_t:s0 tclass=tcp_socket permissive=0
```

`httpd_t` не имеет права биндить `unreserved_port_t:tcp_socket` — порт 4881 не привязан ни к одному известному SELinux-типу.

### Способ 1. setsebool

```
# setsebool -P nis_enabled on     # audit2why указал на этот boolean
# systemctl start nginx           → active (running)
# curl http://127.0.0.1:4881/     → 200
# getsebool nis_enabled           → on
# setsebool -P nis_enabled off    # откат — nginx снова не стартует
```

Минус: boolean предназначен для NIS, включение его ослабляет политику шире, чем нужно.

### Способ 2. semanage port (добавление порта в имеющийся тип)

```
# semanage port -a -t http_port_t -p tcp 4881
# semanage port -l | grep http_port_t
http_port_t  tcp  4881, 80, 81, 443, 488, 8008, 8009, 8443, 9000
# systemctl start nginx           → active, curl → 200
# semanage port -d -t http_port_t -p tcp 4881    # откат
```

Плюс: минимальное точечное изменение, сохраняется после перезагрузки, канонический способ для портов.

### Способ 3. Собственный модуль (audit2allow)

```
# grep nginx /var/log/audit/audit.log | audit2allow -M nginx-port
# semodule -i nginx-port.pp
# systemctl start nginx           → active, curl → 200
# semodule -r nginx-port          # откат
```

Модуль генерируется из логов и разрешает ровно то, что было запрещено (запись в `.te`/`.pp` приложена по пути выполнения — команды в журнале). Минус: слепо разрешает всё, что попало в лог, включая возможные побочные действия; требует поддержки модуля при обновлениях политики.

**Итог задания 1:** все три способа реализованы и продемонстрированы (nginx active + HTTP 200), каждый откатан для проверки следующего.

## 3. Задание 2. DDNS-обновление зоны при включенном SELinux

### Воспроизведение проблемы

С клиента:

```
$ nsupdate -k /etc/named.zonetransfer.key
> server 192.168.1.184
> zone ddns.lab
> update add www.ddns.lab. 60 A 192.168.1.233
> send
update failed: SERVFAIL
```

### Причина

На клиенте ошибок SELinux нет (клиент лишь отправляет пакет). На ns01 в журнале named:

```
client .../key zonetransfer.key: view view1: updating zone 'ddns.lab/IN': adding an RR at 'www.ddns.lab' A 192.168.1.233
/etc/named/dynamic/named.ddns.lab.view1.jnl: create: permission denied
```

и в audit.log:

```
avc: denied { write } for comm="isc-net-0007" name="dynamic"
  scontext=system_u:system_r:named_t:s0
  tcontext=unconfined_u:object_r:named_conf_t:s0 tclass=dir permissive=0
```

**Разбор:** процесс named (`named_t`) пытается создать journal-файл (`.jnl`) для динамической зоны в каталоге `/etc/named/dynamic/`. Каталог размечен типом `named_conf_t` (конфигурационные файлы — только чтение для named), а динамическим зонам нужен тип `named_zone_t` (файлы зон, запись разрешена). Корень проблемы — зоны лежат в `/etc/named`, тогда как по политике файлы зон должны находиться в `/var/named`:

```
# semanage fcontext -l | grep named
/etc/rndc.*          regular file   system_u:object_r:named_conf_t:s0
/var/named(/.*)?     all files      system_u:object_r:named_zone_t:s0
```

Файл зоны в `/etc/named` наследует `named_conf_t`, и named не может ни писать в него, ни создавать рядом `.jnl`.

### Возможные решения

1. **`chcon -R -t named_zone_t /etc/named`** — переклеить контекст файлов зон на `named_zone_t`. Без изменения политики; но chcon-изменения сотрутся при relabel (`restorecon` / `touch /.autorelabel`), т.к. правило fcontext остаётся старым.
2. **`semanage fcontext -a -t named_zone_t '/etc/named(/.*)?'` + restorecon** — то же самое, но правило прописывается в политику и переживает relabel.
3. **audit2allow-модуль** — разрешить `named_t` запись в `named_conf_t`. Плохо: ломает семантику типа (конфиги должны быть read-only для named), расширяет права шире необходимого.
4. **Перенести динамические зоны в `/var/named/dynamic/`** — «правильный» путь по замыслу политики: зоны живут там, где ожидает SELinux, конфиги остаются конфигами. Требует правки путей в `named.conf`.

### Выбранное решение и обоснование

Реализован **способ 1 — chcon**, с точностью до семантики этого стенда:

```
# chcon -R -t named_zone_t /etc/named
# ls -laZ /etc/named/dynamic
drw-rwx---. 2 root  named unconfined_u:object_r:named_zone_t:s0 .
-rw-rw----. 1 named named unconfined_u:object_r:named_zone_t:s0 named.ddns.lab
```

**Обоснование:** стенд учебный и deliberately выносит зоны в `/etc/named`; минимальное изменение контекста демонстрирует сам механизм SELinux (несоответствие контекста → запрет → исправление типа) без правки конфигов приложения. Ограничение способа задокументировано: после relabel контекст вернётся к `named_conf_t` (`restorecon -v -R /etc/named`), и для боевого применения правильнее способ 4 (перенос зон в `/var/named`) или способ 2 (постоянное правило fcontext).

### Демонстрация работоспособности

```
# на клиенте:
$ nsupdate -k /etc/named.zonetransfer.key <<EOF
server 192.168.1.184
zone ddns.lab
update add www.ddns.lab. 60 A 192.168.1.233
send
EOF
exit code 0                                    ← было: update failed: SERVFAIL

$ dig @192.168.1.184 www.ddns.lab +short
192.168.1.233
```

После `systemctl restart named` — зона пересчитывается из journal-файла, запись сохраняется:

```
$ dig @192.168.1.184 www.ddns.lab +short
192.168.1.233                                  ← пережила перезапуск named
```

Обратная операция (`update delete`) также работает, после чего запись добавлена заново.

## 4. Проверка руками

```bash
# ns01 (Iris):
getenforce
systemctl status named
ls -laZ /etc/named /etc/named/dynamic

# client (Irida):
nsupdate -k /etc/named.zonetransfer.key   # server 192.168.1.184; zone ddns.lab; update add ...
dig @192.168.1.184 www.ddns.lab +short
```
