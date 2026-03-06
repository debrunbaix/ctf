# robot

## structures

### Robot

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

### RobotUserGuide

```c
struct RobotUserGuide
{
    char guide[32];
};
```

La structure `RobotUserGuide` permet d'écrire un guide de 32 octets.

Voici la structure dans la heap après avoir écris en guide "AAAAAAAABBBBBBBB\n":

```bash
x/6gx 0x555555559b20
0x555555559b20: 0x0000000000000000      0x0000000000000031
0x555555559b30: 0x4141414141414141      0x4242424242424242
0x555555559b40: 0x000000000000000a      0x0000000000000000
```

## Fonctions

### newRobot()

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

Pour le nom du robot, il va écrire exactement 15 octets de ce que l'utilisateur à entrée dans `name`. 

### admin()

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

La fonction admin permet d'afficher le flag si le Sha256 du mot de passe que nous entrons est le même que celui attendu.
