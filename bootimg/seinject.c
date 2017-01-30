/* 
 * This was derived from public domain works with updates to 
 * work with more modern SELinux libraries. 
 * 
 * It is released into the public domain.
 * 
 */

#include <stdlib.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <sepol/policydb/policydb.h>
#include <sepol/policydb/services.h>

#ifdef WIN32
#define strtok_r strtok_s
#endif

int seinject_quiet = 0;

int seinject_msg(int rc, const char *why, ...)
{
	va_list ap;

	if (seinject_quiet != 0)
		return rc;

	va_start(ap, why);
	fprintf(stderr,"error: ");
	vfprintf(stderr, why, ap);
	fprintf(stderr,"\n");
	va_end(ap);
	return rc;
}


void seinject_die(int rc, const char *why, ...)
{
	va_list ap;

	if (seinject_quiet != 0)
		exit(rc);

	va_start(ap, why);
	fprintf(stderr,"error: ");
	vfprintf(stderr, why, ap);
	fprintf(stderr,"\n");
	va_end(ap);
	exit(rc);
}

void *cmalloc(size_t s) {
	void *t = malloc(s);
	if (t == NULL)
		seinject_die(1, "Out of memory");
	return t;
}

int add_rule(char *s, char *t, char *c, char *p, policydb_t *policy) {
	type_datum_t *src, *tgt;
	class_datum_t *cls;
	perm_datum_t *perm;
	avtab_datum_t *av;
	avtab_key_t key;

	src = (type_datum_t*)hashtab_search(policy->p_types.table, s);
	if (src == NULL)
		return seinject_msg(2, "source type %s does not exist", s);

	tgt = (type_datum_t*)hashtab_search(policy->p_types.table, t);
	if (tgt == NULL)
		return seinject_msg(2, "target type %s does not exist", t);

	cls = (class_datum_t*)hashtab_search(policy->p_classes.table, c);
	if (cls == NULL)
		return seinject_msg(2,"class %s does not exist", c);

	perm = (perm_datum_t*)hashtab_search(cls->permissions.table, p);
	if (perm == NULL) {
		if (cls->comdatum == NULL)
			return seinject_msg(2, "perm %s does not exist in class %s", p, c);

		perm = (perm_datum_t*)hashtab_search(cls->comdatum->permissions.table, p);
		if (perm == NULL)
			return seinject_msg(2, "perm %s does not exist in class %s", p, c);
	}

	// See if there is already a rule
	key.source_type = src->s.value;
	key.target_type = tgt->s.value;
	key.target_class = cls->s.value;
	key.specified = AVTAB_ALLOWED;
	av = avtab_search(&policy->te_avtab, &key);

	if (av == NULL) {
		int ret;

		av = (avtab_datum_t*)cmalloc(sizeof av);
		av->data |= 1U << (perm->s.value - 1);
		ret = avtab_insert(&policy->te_avtab, &key, av);
		if (ret)
			return seinject_msg(1, "Error inserting into avtab");
	}

	av->data |= 1U << (perm->s.value - 1);

	return 0;
}

int add_genfs(char *fs, char *p, char *c, policydb_t *policy) {
	type_datum_t		*tgt;
	genfs_t				*genfs;
	ocontext_t			*octx;
	context_struct_t	*ctx;
	char				*path;

	path = p ? p : "/";

	tgt = (type_datum_t*)hashtab_search(policy->p_types.table, c);
	if (tgt == NULL)
		return seinject_msg(2, "target type %s does not exist", c);

	for (genfs = policy->genfs; genfs; genfs = genfs->next) {
		if (strcmp(genfs->fstype, fs))
			continue;

		for (octx = genfs->head; octx; octx = octx->next) {
			if (0 == strcmp(octx->u.name, path)) {
				octx->context[0].type = tgt->s.value;
				return 0;
			}
		}

		octx = (ocontext_t*)malloc(sizeof(ocontext_t));
		memset(octx, 0, sizeof(ocontext_t));
		octx->next = genfs->head;
		genfs->head = octx;
		break;
	}

	if (!genfs) {
		genfs = (genfs_t*)malloc(sizeof(genfs_t));
		genfs->fstype = strdup(fs);
		octx = (ocontext_t*)malloc(sizeof(ocontext_t));
		memset(octx, 0, sizeof(ocontext_t));
		genfs->head = octx;
		genfs->next = policy->genfs;
		policy->genfs = genfs;
	}

	octx->u.name = strdup(path);

	ctx = octx->context;
	ctx->user = 1;
	ctx->role = 1;
	ctx->type = tgt->s.value;
	ctx->range.level[0].sens = 1;
	ctx->range.level[1].sens = 1;
	return 0;
}

int load_policy(char *filename, policydb_t *policydb, struct policy_file *pf) {
	FILE*	f;
	size_t	size;
	void *data;
	int ret;

	f = fopen(filename, "rb");
	if (f == NULL)
		seinject_die(1, "Can't open '%s':  %s", filename, strerror(errno));

	fseek(f, 0, SEEK_END);
	size = ftell(f);
	fseek(f, 0, SEEK_SET);

	data = malloc(size);
	if (data == NULL) {
		fclose(f);
		seinject_die(1, "Can't allocate memory");
	}

	if (fread(data, 1, size, f) != size) {
		free(data);
		fclose(f);
		seinject_die(1, "Can't read policy file '%s':  %s", filename, strerror(errno));
	}

	policy_file_init(pf);
	pf->type = PF_USE_MEMORY;
	pf->data = (char*)data;
	pf->len = size;
	if (policydb_init(policydb)) {
		free(data);
		fclose(f);
		seinject_die(1, "policydb_init: Out of memory!");
	}

	ret = policydb_read(policydb, pf, 1);
	if (ret) {
		free(data);
		fclose(f);
		seinject_die(1, "error(s) encountered while parsing configuration");
	}

	free(data);
	fclose(f);
	return 0;
}

int load_policy_into_kernel(policydb_t *policydb) {
	FILE	*f;
	char *filename = "/sys/fs/selinux/load";
	int ret;
	void *data = NULL;
	size_t len;

	policydb_to_image(NULL, policydb, &data, &len);

	// based on libselinux security_load_policy()
	f = fopen(filename, "wb");
	if (f == NULL)
		seinject_die(1, "Can't open '%s':  %s", filename, strerror(errno));

	ret = fwrite(data, 1, len, f);
	fclose(f);

	if (ret < 0)
		seinject_die(1, "Could not write policy to %s", filename);

	return 0;
}

int main_seinject(int argc, char **argv) {
	char		*policy = NULL, *source = NULL, *target = NULL, *clazz = NULL, *perm = NULL;
	char		*perm_token = NULL, *perm_saveptr = NULL, *outfile = NULL;
	char		*permissive = NULL, *genfs = NULL;
	policydb_t	policydb;
	struct policy_file pf, outpf;
	sidtab_t sidtab;
	int ret_add_rule;
	int load = 0;
	FILE *fp;
	int i;

	for (i=1; i<argc; i++) {
		if (argv[i][0] == '-') {
			if (argv[i][1] == 's') {
				i++;
				source = argv[i];
				continue;
			}
			if (argv[i][1] == 't') {
				i++;
				target = argv[i];
				continue;
			}
			if (argv[i][1] == 'c') {
				i++;
				clazz = argv[i];
				continue;
			}
			if (argv[i][1] == 'p') {
				i++;
				perm = argv[i];
				continue;
			}
			if (argv[i][1] == 'P') {
				i++;
				policy = argv[i];
				continue;
			}
			if (argv[i][1] == 'o') {
				i++;
				outfile = argv[i];
				continue;
			}
			if (argv[i][1] == 'Z') {
				i++;
				permissive = argv[i];
				continue;
			}
			if (argv[i][1] == 'g') {
				i++;
				genfs = argv[i];
				continue;
			}
			if (argv[i][1] == 'l') {
				load = 1;
				continue;
			}
			if (argv[i][1] == 'q') {
				seinject_quiet = 1;
				continue;
			}
			break;
		}
	}

	if (i < argc || argc == 1 || ((!source || !target || !clazz || !perm) && !permissive && (!genfs || !target))) {
		fprintf(stderr, "%s -s <source type> -t <target type> -c <class> -p <perm>[,<perm2>,<perm3>,...] [-P <policy file>] [-o <output file>] [-l|--load]\n", argv[0]);
		fprintf(stderr, "%s -Z permissive_type [-P <policy file>] [-o <output file>] [-l|--load]\n", argv[0]);
		fprintf(stderr, "%s -g file system -t <target type> [-p path ] [-P <policy file>] [-o <output file>] [-l|--load]\n", argv[0]);
		exit(1);
	}

	if (!policy)
		policy = "/sys/fs/selinux/policy";

	sepol_set_policydb(&policydb);
	sepol_set_sidtab(&sidtab);

	if (load_policy(policy, &policydb, &pf))
		seinject_die(1, "Could not load policy");

	if (policydb_load_isids(&policydb, &sidtab))
		return 1;

	if (permissive) {
		type_datum_t *type;
		type = hashtab_search(policydb.p_types.table, permissive);
		if (type == NULL)
			seinject_die(2, "type %s does not exist", permissive);

		if (ebitmap_set_bit(&policydb.permissive_map, type->s.value, 1))
			seinject_die(1, "Could not set bit in permissive map");
	} else if (genfs) {
		if (add_genfs(genfs, perm, target, &policydb))
			seinject_die(1, "Could not add genfs rule");
	} else {
		perm_token = strtok_r(perm, ",", &perm_saveptr);
		while (perm_token) {
			ret_add_rule = add_rule(source, target, clazz, perm_token, &policydb);
			if (ret_add_rule)
				seinject_die(ret_add_rule, "Could not add rule for perm: %s", perm_token);

			perm_token = strtok_r(NULL, ",", &perm_saveptr);
		}
	}

	if (outfile) {
		fp = fopen(outfile, "wb");
		if (!fp)
			seinject_die(1, "Could not open outfile");

		policy_file_init(&outpf);
		outpf.type = PF_USE_STDIO;
		outpf.fp = fp;

		if (policydb_write(&policydb, &outpf))
			seinject_die(1, "Could not write policy");

		fclose(fp);
	}

	if (load) {
		if (load_policy_into_kernel(&policydb))
			seinject_die(1, "Could not load new policy into kernel");
	}

	policydb_destroy(&policydb);

	if (seinject_quiet == 0)
		fprintf(stderr,"Success\n");

	return 0;
}

void ERR(sepol_handle_t *handle, ...)
{
}

void INFO(sepol_handle_t *handle, ...)
{
}

void WARN(sepol_handle_t *handle, ...)
{
}
