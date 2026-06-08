# Huong dan demo SAINT voi 2 may Win10 VMware va Render

Ap dung cho bo demo gon nhe, tranh lag khi chay nhieu VM song song:

- Web controller: `https://firewall-controller.onrender.com`
- Agent build: `dist/SAINT.exe`
- Hai may Windows 10 trong VMware: `PC1`, `PC2`
- Muc tieu: demo day du cac chuc nang chinh cua he thong SAINT (group, whitelist, override, teacher profile, logs, audit) chi voi 2 VM bang cach lam tuan tu cac override tren cung mot may.

Tai sao 2 VM thay vi 4: chay 4 VM dong thoi tren mot host thuong khien CPU/RAM bi nghen, video demo bi giat. Voi 2 VM, ta van cover du moi tinh nang bang cach thay doi state tuan tu (vi du PC1 lan luot Normal -> Custom Whitelist -> Isolate -> Normal).

## 1. Y tuong demo tong the

Thong diep chinh khi demo:

> SAINT la he thong quan ly truy cap mang tap trung cho phong may. Admin cau hinh user, API key, group, whitelist va policy tren web controller. Agent tren tung may Windows tu dang ky, dong bo whitelist, ap dung Windows Firewall theo che do whitelist-only, ghi log truy cap va gui ve server theo thoi gian thuc. Teacher chi thay va thao tac tren lab duoc gan, dung Whitelist Profile de phuc vu tung buoi hoc.

Phan vai 2 VM:

| May | Group | Vai tro demo | Cac trang thai se di qua |
| --- | --- | --- | --- |
| `PC1` | `Phong 1` | May Phong 1, dien vien chinh cho cac override per-agent | Normal -> Custom Whitelist -> Normal -> Isolate -> Normal |
| `PC2` | `Phong 2` | May Phong 2, dien vien chinh cho Teacher Profile va RBAC | Group default -> Profile Tiet 1 -> Profile Tiet 2 -> Group default |

Y tuong sap xep:

- Phan group/whitelist co ban duoc demo cho ca 2 may.
- Cac override per-agent (Custom Whitelist, Isolate) demo tren `PC1` theo dang "truoc va sau" thay vi so sanh hai may song song.
- Teacher Profile demo tren `PC2` vi day la nhom cua ca hai teacher.
- Neu may host du khoe, co the mo them tab browser tren PC1 trong khi PC2 dang chay profile, nhung khong bat buoc.

## 2. Chuan bi truoc khi demo (Before Demo Checklist)

Lam tat ca cac muc duoi day **truoc khi bam record**. Sap xep theo thu tu thuc hien.

### 2.1. Kiem tra web controller deploy

Mo truoc cac URL nay de danh thuc Render va tranh cold start luc demo:

- `https://firewall-controller.onrender.com`
- `https://firewall-controller.onrender.com/api/health`

Ket qua mong doi cua health:

```json
{
  "architecture": "MVC",
  "status": "healthy",
  "version": "1.0.0"
}
```

Neu trang dau cham, cho 30-60 giay roi refresh. Khong bat dau quay neu health chua `healthy`.

### 2.2. Chuan bi tai khoan

Tai lieu test mac dinh co:

- Admin: `admin / <admin_password>`
- Teacher demo:
  - `teacher_network / Teacher@123456`
  - `teacher_web / Teacher@123456`

Neu ban da doi password tren Render, dung thong tin that. Khong de lo password trong video qua lau.

Neu hai teacher chua ton tai, tao truoc o buoc 2.6 hoac trong demo (Phan 2).

### 2.3. Chuan bi API key cho agent

Vao web bang Admin:

1. Mo `API Keys`.
2. Chon `Create New Key`.
3. Dat ten: `VMware Demo Agents`.
4. Expiration: chon `30 days` hoac `90 days`.
5. Neu UI co permissions, chon `agent_register`. Neu UI chi tao key mac dinh, permission legacy `register` van du de agent dang ky.
6. Bam generate va copy plaintext key ngay lap tuc.

Luu y:

- API key chi hien mot lan. Luu vao file tam tren may host, sau demo xoa di.
- Khong revoke key dang dung. Neu can demo revoke, tao mot key phu o Phan 13.

### 2.4. Chuan bi 2 may Win10 VMware

Tren ca `PC1` va `PC2`:

1. Dat hostname dung: `PC1` va `PC2` (Settings -> System -> Rename this PC, restart).
2. Dam bao co Internet den Render (`ping` hoac browser).
3. Copy `dist/SAINT.exe` vao Desktop.
4. **Tao snapshot VM truoc khi bat firewall enforcement.** Day la phao cuu sinh quan trong nhat.
5. Mo `SAINT.exe` bang `Run as administrator`. Khong run admin se khien agent o trang thai `Degraded`.
6. Neu can packet capture chi tiet, dam bao Npcap da cai. Thieu Npcap thi firewall/whitelist van chay, chi mat detail log.

Lenh kiem tra nhanh tren moi VM neu can:

```powershell
hostname
Test-NetConnection firewall-controller.onrender.com -Port 443
netsh advfirewall show allprofiles
```

### 2.5. Cau hinh agent tren tung may

Tren `SAINT.exe` cua tung PC:

1. Mo tab `Settings`.
2. Server URL: `https://firewall-controller.onrender.com`
3. API Key: dan key vua tao o 2.3.
4. Luu settings.
5. Quay ve tab `Dashboard`. **Khong bam Start Agent voi luc**, de buoc Start xay ra trong demo cho tu nhien.

Khong dan URL co path nhu `/api-keys`. Agent co logic normalize URL, nhung luc demo nen de root URL cho de giai thich.

### 2.6. Tao truoc du lieu nen (toi uu thoi luong demo)

Truoc khi quay, lam san cac viec sau de demo khong qua dai:

| Hang muc | Lam truoc | Lam trong demo |
| --- | --- | --- |
| 2 teacher accounts | Co (kiem tra ton tai) | Khong (chi show trong Users list) |
| API key `VMware Demo Agents` | Co (da tao o 2.3) | Khong |
| 2 group `Phong 1`, `Phong 2` | **Khong** | Co (la dien bien chinh) |
| Bulk whitelist 2 phong | **Khong** | Co (Phan 5) |
| Map view layout | Tuy chon | Tuy chon |
| Teacher Profile cua 2 teacher | **Khong** | Co (Phan 10) |

Tom lai: teacher account + API key tao truoc; group, whitelist va profile de demo truc tiep.

### 2.7. Du lieu demo nen su dung

| Loai | Gia tri goi y |
| --- | --- |
| Group 1 | `Phong 1` |
| Description 1 | `General Practice, Basic Internet Access` |
| Agent Phong 1 | `PC1` |
| Whitelist Phong 1 | Bulk list: `example.com`, `wikipedia.org`, `www.wikipedia.org`, `vi.wikipedia.org`, `khanacademy.org`, `www.khanacademy.org`, `python.org`, `www.python.org`, `docs.python.org`, `stackoverflow.com`, `www.stackoverflow.com`, `geeksforgeeks.org`, `www.geeksforgeeks.org` |
| Group 2 | `Phong 2` |
| Description 2 | `Computer Network, Web Development` |
| Agent Phong 2 | `PC2` |
| Whitelist Phong 2 | Bulk list: `developer.mozilla.org`, `w3schools.com`, `www.w3schools.com`, `github.com`, `docs.github.com`, `raw.githubusercontent.com`, `github.githubassets.com`, `objects.githubusercontent.com`, `learn.microsoft.com`, `nodejs.org`, `www.nodejs.org`, `npmjs.com`, `www.npmjs.com`, `pypi.org`, `files.pythonhosted.org`, `caniuse.com` |
| Teachers | `teacher_network` va `teacher_web` chi gan vao `Phong 2` de demo RBAC |
| Domain de test blocked | `facebook.com`, `youtube.com`, `vnexpress.net` |
| Custom whitelist PC1 | `wikipedia.org` |
| Teacher profile 1 | `Tiet 1 - Computer Network` cua `teacher_network` trong `Phong 2` |
| Profile 1 domains | `wireshark.org`, `www.wireshark.org`, `ietf.org`, `rfc-editor.org`, `cloudflare.com`, `learn.microsoft.com` |
| Teacher profile 2 | `Tiet 2 - Web Development` cua `teacher_web` trong `Phong 2` |
| Profile 2 domains | `developer.mozilla.org`, `w3schools.com`, `www.w3schools.com`, `github.com`, `docs.github.com`, `caniuse.com` |

Meo chon domain:

- Dung `example.com` de test allowed vi trang don gian, it phu thuoc CDN.
- Dung `facebook.com` hoac `youtube.com` de test blocked.
- Khong dung wildcard lam test firewall chinh. Source hien tai chi DNS-resolve exact domain thanh IP rule.

### 2.8. Checklist truoc khi bam record

In ra hoac dan ben canh man hinh:

- [ ] Render health response `healthy`.
- [ ] Admin login duoc.
- [ ] `teacher_network` va `teacher_web` da ton tai.
- [ ] API key `VMware Demo Agents` da tao va copy.
- [ ] `PC1` va `PC2` co hostname dung, da snapshot.
- [ ] `SAINT.exe` co tren ca `PC1` va `PC2`.
- [ ] Ca 2 VM mo `SAINT.exe` bang `Run as administrator`.
- [ ] Ca 2 VM da dan Server URL va API key vao Settings, **chua bam Start**.
- [ ] Browser tren may host zoom 110-125% de chu de doc.
- [ ] Windows notifications tat tren VM va host.
- [ ] Da co file tam de copy/paste danh sach domain whitelist (de bulk paste nhanh).
- [ ] Da biet nut `Restore firewall` nam o Settings cua SAINT.
- [ ] Tab browser tren VM da mo san: `example.com`, `facebook.com`, `wikipedia.org`, `github.com`, `developer.mozilla.org`, `wireshark.org` (nhung **chua refresh** cho den khi demo).
- [ ] Doi voi quay screen: chi share man hinh, khong share notification panel.

## 3. Kich ban demo day du

Thoi luong goi y: 9-12 phut voi 2 VM. Neu can ngan hon 7 phut, bo Phan 12 (Audit chi tiet) va Phan 13 (Revoke API key).

### Phan 1 - Gioi thieu va dashboard

Thao tac:

1. Mo `https://firewall-controller.onrender.com`.
2. Mo them `/api/health` de show server healthy.
3. Dang nhap Admin.
4. Show Dashboard: Total Logs, Allowed, Blocked, Active Agents, System Health.

Loi noi goi y:

> Day la web controller cua SAINT da deploy tren Render. Controller dung Flask, MongoDB va SocketIO de quan ly tap trung cac agent trong phong may. Dashboard cho biet tong quan trang thai he thong, agent online va log truy cap mang theo thoi gian thuc.

### Phan 2 - User, API key va RBAC nen tang

Thao tac Admin:

1. Vao `Users`.
2. Show da co `teacher_network` va `teacher_web` voi role `Teacher`. Neu chua co, tao tai cho:
   - `teacher_network`, password `Teacher@123456`, role `Teacher`.
   - `teacher_web`, password `Teacher@123456`, role `Teacher`.
3. Vao `API Keys`, show key `VMware Demo Agents` da tao.

Loi noi goi y:

> He thong tach hai loai dinh danh. Nguoi dung web dang nhap bang username/password va duoc phan quyen RBAC. May agent khong dung tai khoan nguoi dung, ma dang ky bang API key, sau do server cap JWT cho heartbeat, whitelist sync va gui log.

### Phan 3 - Dang ky 2 agent PC1 va PC2

Thao tac tren 2 VM:

1. Mo `SAINT.exe` bang Administrator (da mo tu truoc).
2. Vao `Settings`, xac nhan Server URL va API key (da dan tu truoc).
3. Bam `Start Agent` tren `PC1`, doi status `Running` hoac `Degraded`.
4. Lap lai cho `PC2`.

Thao tac tren web:

1. Vao `Agents`.
2. Bam `Refresh`.
3. Show `PC1` va `PC2` xuat hien, status online/active.
4. Doi display name neu can.

Loi noi goi y:

> Khi bam Start, agent gui hostname, device id, IP va OS info len server. Server validate API key, tao hoac update agent record, tra ve agent_id va JWT. Sau do agent gui heartbeat dinh ky 20 giay, nen dashboard biet duoc may nao dang online.

Neu agent hien `Degraded`:

- Neu khong co admin: firewall enforcement bi disable, phai mo lai bang Run as administrator.
- Neu sniffer skipped: co the thieu Npcap, nhung whitelist/firewall van co the demo.
- Neu registration failed: kiem tra API key, Server URL, Internet va Render health.

### Phan 4 - Tao 2 phong lab va gan 2 may

Thao tac:

1. Vao `Groups`.
2. Tao group `Phong 1`.
   - Description: `General Practice, Basic Internet Access`.
3. Tao group `Phong 2`.
   - Description: `Computer Network, Web Development`.
4. Gan `PC1` vao `Phong 1`.
5. Gan `PC2` vao `Phong 2`.
6. Mo detail `Phong 1`, chuyen sang `Map View`, dat layout `1 row x 1 column`, keo `PC1` vao o.
7. Mo detail `Phong 2`, chuyen sang `Map View`, dat layout `1 row x 1 column`, keo `PC2` vao o.
8. Trong `Phong 2`, gan `teacher_network` va `teacher_web` vao panel `Assigned Teachers`.
9. Khong gan hai teacher nay vao `Phong 1` de khi login Teacher RBAC chi hien `Phong 2`.

Loi noi goi y:

> Group dai dien cho mot phong lab hoac lop hoc. O demo nay, PC1 thuoc Phong 1, PC2 thuoc Phong 2. Hai giao vien demo chi duoc gan vao Phong 2, nen khi dang nhap se khong thay du lieu cua Phong 1, the hien RBAC. Demo dang gon vi muc dich la show kien truc, khong phai size phong that.

### Phan 5 - Quan ly whitelist cua group

Thao tac Admin:

1. Mo trang `Whitelist`.
2. Chon `Bulk` / `Bulk Add`.
3. Import cho `Phong 1`, scope `Group`, target `Phong 1`, default type `Auto-detect` hoac `Domain`, paste danh sach:

```text
example.com
wikipedia.org
www.wikipedia.org
vi.wikipedia.org
khanacademy.org
www.khanacademy.org
python.org
www.python.org
docs.python.org
stackoverflow.com
www.stackoverflow.com
geeksforgeeks.org
www.geeksforgeeks.org
```

4. Import cho `Phong 2`, scope `Group`, target `Phong 2`, default type `Auto-detect` hoac `Domain`, paste danh sach:

```text
developer.mozilla.org
w3schools.com
www.w3schools.com
github.com
docs.github.com
raw.githubusercontent.com
github.githubassets.com
objects.githubusercontent.com
learn.microsoft.com
nodejs.org
www.nodejs.org
npmjs.com
www.npmjs.com
pypi.org
files.pythonhosted.org
caniuse.com
```

5. Sau khi import, show counters `Total Items`, `Active Items`, `Domains`.
6. Show filter:
   - All Groups
   - Group `Phong 1`
   - Group `Phong 2`
   - Type Domain/IP/URL
   - Status Active/Inactive
7. Demo inactive:
   - Chon mot item, `Deactivate`.
   - Giai thich item inactive van hien trong management UI nhung khong sync xuong agent.
   - Activate lai de tiep tuc demo.

Loi noi goi y:

> Whitelist co scope global va group. Bulk import giup admin nap nhanh danh sach website cho tung phong thuc hanh thay vi them tung domain mot. Agent sync effective policy theo cong thuc global active cong voi group active, hoac global active cong voi active teacher profile. Version cua whitelist tang moi khi co thay doi, giup agent biet khi nao can cap nhat firewall rules.

### Phan 6 - Agent sync whitelist va ap dung firewall

Thao tac tren `PC1`:

1. Mo tab `Whitelist`.
2. Bam `Refresh` hoac `Sync Now`.
3. Show danh sach domains vua cau hinh.
4. Bat hien resolved IPs neu can.
5. Mo tab `Firewall Rules`.
6. Show mode whitelist-only/default deny va danh sach allow rules co prefix `FirewallController`.

Lam tuong tu nhanh tren `PC2` neu muon show cho ca 2 phong.

Loi noi goi y:

> Agent lay whitelist tu server, tach domain/IP/pattern, resolve exact domain thanh IPv4, them IP he thong quan trong nhu DNS, gateway, local host va server controller, sau do tao Windows Firewall allow rules. Sau khi rules an toan da tao xong, agent moi bat default deny outbound de tranh tu khoa mang.

### Phan 7 - Test allowed va blocked tren PC1

Thao tac tren `PC1`:

1. Mo browser vao `https://example.com`. Trang load duoc.
2. Mo `https://facebook.com` hoac `https://youtube.com`. Trang khong load hoac timeout.
3. Mo `https://wikipedia.org` de show domain thuoc Phong 1 whitelist van vao duoc.
4. Quay ve Agent `Dashboard` va `Logs`, show event allowed/blocked neu co.

Thao tac tren web:

1. Vao `Logs`.
2. Filter Agent = `PC1`.
3. Show log allowed/blocked/warning.
4. Bam log detail neu can.

Loi noi goi y:

> Day la diem khac biet chinh cua SAINT: policy duoc quan ly tap trung, nhung enforcement nam tren tung endpoint bang Windows Firewall. Server khong can lam proxy. Agent vua chan o layer 3 bang IP allow rules, vua dung sniffer de ghi nhan domain va gui log ve server.

Neu log khong hien ngay:

- Doi 2-5 giay vi LogSender gui batch.
- Refresh Logs.
- Kiem tra `PC1` Agent Logs view co log local khong.

### Phan 8 - Override per-agent: Custom Whitelist cho PC1

**Tinh huong:** Trong tiet kiem tra, admin chi cho PC1 vao Wikipedia, khong cho vao cac trang khac cua phong.

Thao tac tren web:

1. Vao group detail `Phong 1`.
2. Right-click card `PC1`.
3. Chon `Custom Whitelist`.
4. Reason: `Chi cho lam bai Wikipedia`.
5. Duration: `15 minutes` (du dai de hoan thanh phan demo, nhung tu het han neu quen).
6. Add domain: `wikipedia.org`.
7. Apply.
8. Show badge `Custom` tren PC1.

Thao tac tren `PC1`:

1. Bam Sync Now hoac doi heartbeat/sync.
2. Refresh tab `https://wikipedia.org`: van duoc.
3. Refresh tab `https://example.com`: bi chan hoac khong load, **du `Phong 1` group whitelist co `example.com`**. Day la diem chot.
4. Mo tab `Logs` tren agent neu muon show local event.

Loi noi goi y:

> Day la override per-agent. Khi mot may co Custom Whitelist, no khong dung whitelist chung cua phong nua ma chi dung danh sach rieng. Dung khi mot may kiem tra hoac chi can vao mot tap website nho.

**Quan trong**: Phai go Custom Whitelist truoc khi sang Phan 9 de PC1 quay ve group default, neu khong demo Isolate se bi nhieu nguyen nhan.

Thao tac go:

1. Tren web, vao detail `Phong 1`, right-click PC1, chon `Reset to Default` hoac `Clear Custom Policy`.
2. PC1 Sync Now, test lai `example.com` -> load duoc.

### Phan 9 - Override per-agent: Isolate PC1

**Tinh huong:** PC1 bi phat hien vi pham, admin tam co lap may khoi mang.

Thao tac tren web:

1. Trong group detail `Phong 1`, right-click `PC1`.
2. Chon `Isolate`.
3. Reason: `Vi pham trong gio hoc`.
4. Duration: `5 minutes`.
5. Confirm.
6. Show badge `Isolated`.

Thao tac tren `PC1`:

1. Sync hoac doi heartbeat.
2. Thu vao `https://example.com`, `https://wikipedia.org`. **Ca hai khong load** vi `PC1` dang bi isolate.
3. Show controller van nhan duoc heartbeat tu PC1 (web `Agents` van thay online).

Thao tac tren web sau khi demo xong:

1. Right-click PC1, chon `Reset to Default` de go isolate.
2. PC1 Sync Now, test lai `example.com` -> load duoc.

Loi noi goi y:

> Isolate khong phai xoa agent hay tat may. No la policy override tren server. Agent van giu duong ve controller de teacher/admin co the go co lap tu xa, tranh deadlock. Khac voi Custom Whitelist o cho Isolate chan toan bo, con Custom chi chan ngoai danh sach rieng.

### Phan 10 - Teacher Profile theo tung tiet hoc (PC2)

Y tuong can noi ro:

- `Group Whitelist` la whitelist mac dinh cua phong.
- Neu giao vien khong bat profile nao, agent dung whitelist mac dinh nay.
- Moi tiet hoc co the co mot teacher/profile rieng.
- Trong cung mot group, chi mot Teacher Profile active tai mot thoi diem.
- Khi profile active, group base whitelist bi override; global whitelist neu co van duoc giu.

#### 10.1. Trang thai mac dinh: khong bat profile

Thao tac:

1. Dam bao trong `Phong 2` chua co profile active, hoac deactivate profile dang active.
2. Tren `PC2`, Sync Now.
3. Test mot domain trong group whitelist mac dinh cua `Phong 2`, vi du `https://github.com` hoac `https://developer.mozilla.org`.
4. Domain load duoc.

Loi noi goi y:

> Day la che do fallback. Neu giao vien quen khong bat profile, phong van co whitelist chung do Admin cau hinh san, nen hoc sinh van co bo website toi thieu de thuc hanh.

#### 10.2. Tiet 1: giao vien Computer Network bat profile rieng

Thao tac:

1. Logout Admin.
2. Dang nhap `teacher_network`.
3. **Show RBAC**: Teacher chi thay group `Phong 2`, khong thay `Phong 1`.
4. Show menu Admin-only nhu `Users`, `API Keys`, `Audit` khong con hoac bi chan.
5. Mo group detail `Phong 2`.
6. Tao Teacher Profile ten `Tiet 1 - Computer Network`.
7. Edit rules/domains cho profile:

```text
wireshark.org
www.wireshark.org
ietf.org
rfc-editor.org
cloudflare.com
learn.microsoft.com
```

8. Activate profile.
9. Show banner `Teacher Profile Active`.

Thao tac tren `PC2`:

1. Sync Now hoac doi sync.
2. Test domain trong tiet Computer Network, vi du `https://www.wireshark.org`: duoc.
3. Test domain chi co trong group base/Web Dev, vi du `https://github.com`: co the bi chan neu profile khong chua domain nay.

Loi noi goi y:

> Khi thay day Computer Network bat profile, agent trong Phong 2 nhan bo whitelist cua tiet Network. Danh sach chung cua phong tam thoi khong con la policy chinh nua.

#### 10.3. Tiet 2: giao vien Web Development thay profile

Thao tac:

1. Logout `teacher_network`.
2. Dang nhap `teacher_web`.
3. Mo `Phong 2`.
4. Tao Teacher Profile ten `Tiet 2 - Web Development`.
5. Edit rules/domains cho profile:

```text
developer.mozilla.org
w3schools.com
www.w3schools.com
github.com
docs.github.com
caniuse.com
```

6. Activate profile.
7. Neu UI bao profile Network dang active, confirm de activate Web Development. He thong se deactivate profile cu trong cung group.
8. Show banner doi sang `Tiet 2 - Web Development`.

Thao tac tren `PC2`:

1. Sync Now hoac doi sync.
2. Test `https://developer.mozilla.org` hoac `https://github.com`: duoc.
3. Test `https://www.wireshark.org`: co the bi chan vi khong nam trong profile Web Development.

Loi noi goi y:

> Moi tiet hoc co mot profile rieng. Khi tiet Web Development bat dau, giao vien Web activate profile cua minh; profile Computer Network tu dong het hieu luc trong phong nay.

#### 10.4. Het tiet: tat profile va quay ve group whitelist

Thao tac:

1. `teacher_web` deactivate profile Web Development.
2. Show banner fallback ve group default.
3. Tren `PC2`, Sync Now.
4. Test lai mot domain trong group whitelist mac dinh cua `Phong 2`, vi du `https://github.com`.

Loi noi goi y:

> Khi het tiet, giao vien tat profile. Phong quay lai whitelist chung cua Admin. Day la thiet ke de group whitelist dong vai tro nen an toan, con Teacher Profile la policy dong theo tung tiet hoc.

### Phan 11 - Logs, export va realtime

Thao tac bang Admin:

1. Dang nhap lai Admin.
2. Vao `Logs`.
3. Filter:
   - Agent: `PC1`, `PC2`
   - Level/action: Allowed, Blocked, Warning, Error, Info
   - Time: Last Hour / Last 24 Hours
4. Bam `Export` de tai CSV/JSON neu can.
5. Khong clear all logs truoc khi quay xong. Neu demo clear, export truoc.

Loi noi goi y:

> Logs la kenh detective control. Ngoai viec chan traffic, he thong con luu duoc ai, may nao, thoi diem nao, domain nao duoc phep hoac bi chan. Teacher chi thay log trong group minh duoc gan; Admin thay toan he thong va co quyen export/clear.

### Phan 12 - Audit, profile ca nhan va doi mat khau

Thao tac bang Admin:

1. Vao `Audit`.
2. Show log login, create user, whitelist change, profile activate neu co.
3. Filter action/resource.
4. Vao `Profile & Password`.
5. Show update email va change password UI. Khong doi password that trong demo neu khong can.

Loi noi goi y:

> Audit log ghi lai hanh dong quan tri quan trong. Voi he thong dieu khien truy cap mang, audit giup truy vet ai da tao user, thay doi whitelist, activate profile hoac dang nhap he thong.

### Phan 13 - API key revoke demo (tuy chon, lam cuoi)

Chi demo sau khi da quay xong phan agent chinh, vi revoke sai key co the lam agent moi khong register lai duoc.

Thao tac:

1. Vao `API Keys`.
2. Tao key phu ten `Temporary Revoked Demo`.
3. Copy key.
4. Bam `Revoke`.
5. Stop `PC2`, thay API key trong Settings bang key vua revoke, bam Start.
6. Show registration failed.
7. Doi lai key chinh `VMware Demo Agents` cho `PC2` va Start lai.

Loi noi goi y:

> API key chi dung cho enrollment. Khi key bi revoke hoac expired, agent moi khong duoc tin cay va server khong cap identity/JWT. Day la co che thu hoi quyen dang ky endpoint.

## 4. Sau demo (After Demo Steps)

Thuc hien day du de tra ca 2 VM ve trang thai an toan, khong de Internet bi khoa qua dem.

### 4.1. Stop agent va restore firewall tren tung VM

Tren ca `PC1` va `PC2`:

1. Trong `SAINT.exe`, bam `Stop Agent`. Doi status chuyen `Stopped`.
2. Mo tab `Settings`, bam `Restore firewall`.
3. Bam `Clear SAINT rules` neu muon don sach rule prefix `FirewallController`.
4. Mo browser, vao mot trang nam ngoai whitelist (vi du `https://google.com`). Phai vao duoc thi moi yen tam.

Lenh kiem tra neu can:

```powershell
netsh advfirewall firewall show rule name=all | findstr FirewallController
netsh advfirewall show allprofiles
```

Khong con dong nao output o lenh dau la sach.

### 4.2. Don du lieu tren web controller

Tuy chon, lam khi muon reset cho lan demo sau:

1. Vao `API Keys`, revoke `Temporary Revoked Demo` (neu da tao o Phan 13).
2. Cac group/whitelist/profile co the giu lai cho lan sau hoac xoa tuy y.
3. Khong xoa `VMware Demo Agents` key neu con dinh demo lai.
4. Vao `Logs`, export ra file de luu lich su, sau do co the clear neu can man hinh sach cho lan sau.

### 4.3. Don may host va VM

1. Tat browser tab da mo (`example.com`, `facebook.com`, ...).
2. Xoa file tam chua API key.
3. Snapshot lai 2 VM o trang thai post-demo neu muon co checkpoint moi.
4. Tat 2 VM khi khong dung den.
5. Backup video record sang dia luu tru.

### 4.4. Phong truong hop tham hoa (chi dung khi VM mat mang sau demo)

Neu lo quen Restore firewall va VM khong vao Internet duoc:

```powershell
netsh advfirewall reset
```

Chay trong VM voi quyen Administrator. Lenh nay reset toan bo Windows Firewall ve mac dinh. **Chi dung trong VM/snapshot, khong dung tren may ca nhan** vi se xoa moi cau hinh firewall rieng.

Neu van khong cuu duoc, revert VM ve snapshot da tao o buoc 2.4.

### 4.5. Checklist sau demo

- [ ] Ca 2 agent da Stop.
- [ ] Ca 2 VM da Restore firewall, browse Internet binh thuong.
- [ ] Khong con rule `FirewallController` thua tren VM.
- [ ] Video record da save va backup.
- [ ] File tam chua API key da xoa.
- [ ] Tab browser nhay cam (login admin, ...) da dong.
- [ ] 2 VM da tat hoac snapshot tuy nhu cau.
- [ ] Render dashboard khong con agent online "ma" (PC stop nhung van hien online): doi vai phut roi refresh, neu van con thi vao Agents -> Delete.

## 5. Thu tu demo ngan gon de quay video

Neu can video 7 phut, di theo thu tu nay:

1. Dashboard + health Render.
2. Admin tao 2 group `Phong 1` va `Phong 2`.
3. Start 2 agent `PC1` va `PC2`, show online.
4. Gan `PC1` vao `Phong 1`, `PC2` vao `Phong 2`. Gan 2 teacher vao `Phong 2`.
5. Bulk add whitelist cho tung phong.
6. PC1 test allowed `example.com`, blocked `facebook.com`.
7. PC1 custom whitelist `wikipedia.org` -> show `example.com` bi chan -> Reset.
8. PC1 isolate -> show moi thu bi chan -> Reset.
9. Logs realtime tren web.
10. Login `teacher_network`, RBAC, tao + activate profile `Tiet 1 - Computer Network`.
11. Login `teacher_web`, tao + activate profile `Tiet 2 - Web Development`, show profile cu bi thay the.
12. Deactivate profile de fallback ve group whitelist.
13. Audit ngan + cau ket.

## 6. Loi thuong gap va cach xu ly nhanh

| Hien tuong | Nguyen nhan hay gap | Cach xu ly |
| --- | --- | --- |
| Agent khong hien tren web | Sai URL/API key/Render cold start | Mo `/api/health`, copy lai URL root, tao API key moi |
| Agent `Degraded` | Khong run as admin hoac thieu Npcap | Run as administrator; neu chi thieu sniffer van demo firewall duoc |
| Allowed domain khong load het | Site dung nhieu CDN/subdomain | Dung `example.com` cho test chinh, them exact domain phu neu can |
| Blocked domain van co log cham | LogSender gui batch | Doi vai giay hoac refresh Logs |
| PC1 sau Custom Whitelist van load duoc trang khac | Sync chua xong hoac chua go cache browser | Bam Sync Now tren agent, Ctrl+F5 trong browser |
| Sau khi Reset Custom/Isolate van bi chan | Agent chua sync lai | Bam Sync Now, doi 5-10 giay |
| Teacher khong sua group whitelist | Day la design moi | Teacher dung `Teacher Profiles` |
| Bat profile xong group whitelist bi mat tac dung | Day la design | Active profile override group base whitelist; deactivate profile de quay ve group default |
| Inactive whitelist van hien tren UI | Management UI van hien de quan ly | Giai thich inactive khong sync xuong agent |
| PC mat Internet sau demo | Firewall chua restore | Stop Agent, Settings -> Restore firewall, cuoi cung `netsh advfirewall reset` trong VM |
| Host lag du da giam con 2 VM | RAM/CPU van thieu | Tat browser thua tren host, tat VM khac, giam RAM moi VM xuong 2GB neu chi can demo UI |

## 7. Cau noi ket thuc

> Voi demo 2 may va 2 phong thuc hanh, ta thay duoc toan bo vong doi: Admin tao tai khoan, API key, phong lab va whitelist chung cho tung phong; agent dang ky, heartbeat, sync va enforce tren Windows Firewall; admin co the override tung may bang Custom Whitelist hoac Isolate; moi giao vien bat Teacher Profile rieng cho tiet hoc cua minh; khi het tiet thi tat profile va phong quay ve whitelist chung. Log va audit giup theo doi toan bo thay doi. He thong dat muc tieu quan ly truy cap mang tap trung cho phong may ma khong can proxy trung gian.
