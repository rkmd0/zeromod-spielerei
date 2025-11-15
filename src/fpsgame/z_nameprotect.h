#ifdef Z_NAMEPROTECT_H
#error "already z_nameprotect.h"
#endif
#define Z_NAMEPROTECT_H

#ifndef Z_SERVCMD_H
#error "want z_servcmd.h"
#endif
#ifndef Z_RENAME_H
#error "want z_rename.h"
#endif

// modes for matching reserved identifiers
enum { Z_NP_EXACT = 0, Z_NP_PREFIX = 1 };

struct z_nameguard
{
    char name[MAXNAMELEN+1]; // reserved plain name or tag (sanitized)
    char *user;              // auth user
    char *desc;              // auth realm/desc
    int mode;                // exact or prefix
    z_nameguard() : user(NULL), desc(NULL), mode(Z_NP_EXACT) { name[0] = 0; }
    ~z_nameguard() { DELETEA(user); DELETEA(desc); }
};

static vector<z_nameguard*> z_nameguards;

// sanitize + lowercase so color codes / case don’t bypass checks
static void z_np_normalize(const char *in, string &out)
{
    string tmp;
    filtertext(tmp, in ? in : "", false, false, MAXNAMELEN);
    if(!tmp[0]) copystring(tmp, "unnamed");
    for(char *s = tmp; *s; ++s) *s = tolower(*s);
    copystring(out, tmp);
}

static bool z_np_match(const char *playername, z_nameguard **out = NULL)
{
    if(!playername || !*playername) return false;
    string nrm; z_np_normalize(playername, nrm);
    loopv(z_nameguards)
    {
        z_nameguard *g = z_nameguards[i];
        if(!g || !*g->name || !g->user) continue;
        string gnrm; z_np_normalize(g->name, gnrm);
        bool ok = (g->mode == Z_NP_EXACT) ? !strcmp(nrm, gnrm)
                                          : !strncmp(nrm, gnrm, strlen(gnrm));
        if(ok) { if(out) *out = g; return true; }
    }
    return false;
}

static void z_np_require_auth(clientinfo *ci, z_nameguard *g)
{
    if(!ci || !g) return;
    // remember the identity we require and ask client to auth to that realm
    ci->xi.claim.set(g->user, g->desc);
    ci->xi.authident = true;
    ci->xi.setwlauth(g->desc);
    sendf(ci->clientnum, 1, "ris", N_SERVMSG,
          tempformatstring("the name '%s' is reserved; authenticate with: /auth %s %s",
                           ci->name, g->user, g->desc && *g->desc ? g->desc : serverauth));
}

// gate connection behind auth if name is reserved.
// return a DISC_* code (non-zero -> go into connectauth).
static int z_nameprotect_onconnect(clientinfo *ci)
{
    z_nameguard *g = NULL;
    if(!ci || !z_np_match(ci->name, &g)) return DISC_NONE;

    // already authenticated as owner? Let them in.
    if(ci->xi.ident.isset()
    && !strcasecmp(ci->xi.ident.name, g->user)
    && (!g->desc || !*g->desc || !strcasecmp(ci->xi.ident.desc, g->desc)))
        return DISC_NONE;

    ci->xi.setdiscreason(tempformatstring("the name '%s' is reserved", ci->name));
    z_np_require_auth(ci, g);
    // use DISC_PASSWORD to activate Zeromod's connectauth flow
    return DISC_PASSWORD;
}

// veto renames into a reserved name/tag unless the client owns it.
static bool z_nameprotect_onrename(clientinfo *ci, const char *newname)
{
    z_nameguard *g = NULL;
    if(!ci || !z_np_match(newname, &g)) return false;

    if(ci->xi.ident.isset()
    && !strcasecmp(ci->xi.ident.name, g->user)
    && (!g->desc || !*g->desc || !strcasecmp(ci->xi.ident.desc, g->desc)))
        return false;

    sendf(ci->clientnum, 1, "ris", N_SERVMSG,
          tempformatstring("the name '%s' is reserved; you must /auth %s %s first",
                           newname, g->user, g->desc && *g->desc ? g->desc : serverauth));
    // re-affirm the current name on clients
    z_rename(ci, ci->name, false);
    return true;
}


static void z_servcmd_nameprotect(int argc, char **argv, int sender)
{
    if(argc <= 1) { sendf(sender, 1, "ris", N_SERVMSG, "usage: nameprotect add|del|list ..."); return; }

    if(!strcasecmp(argv[1], "add"))
    {
        if(argc < 6)
        {
            sendf(sender, 1, "ris", N_SERVMSG,
                  "usage: nameprotect add <exact|prefix> <nameOrTag> <authdesc> <user>");
            return;
        }
        int mode = !strcasecmp(argv[2], "prefix") ? Z_NP_PREFIX : Z_NP_EXACT;
        z_nameguard *g = new z_nameguard;
        copystring(g->name, argv[3], MAXNAMELEN+1);
        g->desc = newstring(argv[4]);
        g->user = newstring(argv[5]);
        g->mode = mode;
        z_nameguards.add(g);
        sendf(-1, 1, "ris", N_SERVMSG,
              tempformatstring("reserved %s \"%s\" for %s@%s",
                               mode==Z_NP_PREFIX ? "prefix" : "name", g->name, g->user, g->desc));
    }
    else if(!strcasecmp(argv[1], "del"))
    {
        if(argc < 3) { sendf(sender, 1, "ris", N_SERVMSG, "usage: nameprotect del <nameOrTag>"); return; }
        string nrm; z_np_normalize(argv[2], nrm);
        loopv(z_nameguards)
        {
            string gnrm; z_np_normalize(z_nameguards[i]->name, gnrm);
            if(!strcmp(nrm, gnrm))
            {
                delete z_nameguards.remove(i);
                sendf(-1, 1, "ris", N_SERVMSG, tempformatstring("removed reservation for \"%s\"", argv[2]));
                return;
            }
        }
        sendf(sender, 1, "ris", N_SERVMSG, "not found");
    }
    else if(!strcasecmp(argv[1], "list"))
    {
        sendf(sender, 1, "ris", N_SERVMSG, "reserved names:");
        loopv(z_nameguards)
        {
            z_nameguard *g = z_nameguards[i];
            sendf(sender, 1, "ris", N_SERVMSG,
                  tempformatstring(" - %s \"%s\" -> %s@%s",
                                   g->mode==Z_NP_PREFIX ? "prefix" : "name", g->name, g->user, g->desc));
        }
    }
    else sendf(sender, 1, "ris", N_SERVMSG, "usage: nameprotect add|del|list ...");
}
SCOMMANDA(nameprotect, PRIV_ADMIN, z_servcmd_nameprotect, 1);

#endif // Z_NAMEPROTECT_H
