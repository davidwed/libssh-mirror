/*
 * token.c - Token list handling functions
 *
 * This file is part of the SSH Library
 *
 * Copyright (c) 2003-2008 by Aris Adamantiadis
 * Copyright (c) 2019 by Anderson Toshiyuki Sasaki - Red Hat, Inc.
 *
 * The SSH Library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or (at your
 * option) any later version.
 *
 * The SSH Library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with the SSH Library; see the file COPYING.  If not, write to
 * the Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,
 * MA 02111-1307, USA.
 */

#include "config.h"

#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#include "libssh/priv.h"
#include "libssh/token.h"

/**
 * @internal
 *
 * @brief Free the given tokens list structure. The used buffer is overwritten
 * with zeroes before freed.
 *
 * @param[in] tokens    The pointer to a structure to be freed;
 */
void ssh_tokens_free(struct ssh_tokens_st *tokens)
{
    int i;
    if (tokens == NULL) {
        return;
    }

    if (tokens->tokens != NULL) {
        for (i = 0; tokens->tokens[i] != NULL; i++) {
            explicit_bzero(tokens->tokens[i], strlen(tokens->tokens[i]));
        }
    }

    if (tokens->n_tokens != NULL) {
        for (i = 0; tokens->n_tokens[i] != NULL; i++) {
            explicit_bzero(tokens->n_tokens[i], strlen(tokens->n_tokens[i]));
        }
    }

    SAFE_FREE(tokens->buffer);
    SAFE_FREE(tokens->tokens);
    SAFE_FREE(tokens->n_tokens);
    SAFE_FREE(tokens);
}

/**
 * @internal
 *
 * @brief Split a given string on the given separator character. The returned
 * structure holds an array of pointers (tokens) pointing to the obtained
 * parts and a buffer where all the content of the list is stored. The last
 * element of the array will always be set as NULL.
 *
 * @param[in] chain         The string to split
 * @param[in] separator     The character used to separate the tokens.
 *
 * @return  A newly allocated tokens list structure; NULL in case of error.
 */
struct ssh_tokens_st *ssh_tokenize(const char *chain, char separator)
{

    struct ssh_tokens_st *tokens = NULL;
    size_t num_tokens = 1, i = 1;

    char *found, *c;

    if (chain == NULL) {
        return NULL;
    }

    tokens = calloc(1, sizeof(struct ssh_tokens_st));
    if (tokens == NULL) {
        return NULL;
    }

    tokens->buffer= strdup(chain);
    if (tokens->buffer == NULL) {
        goto error;
    }

    c = tokens->buffer;
    do {
        found = strchr(c, separator);
        if (found != NULL) {
            c = found + 1;
            num_tokens++;
        }
    } while(found != NULL);

    /* Allocate tokens list */
    tokens->tokens = calloc(num_tokens + 1, sizeof(char *));
    tokens->n_tokens = calloc(num_tokens + 1, sizeof(char *));

    if (tokens->tokens == NULL || tokens->n_tokens == NULL) {
        goto error;
    }

    /* First token starts in the beginning of the chain */
    int tok_count = 0;
    int n_tok_count = 0;
    if(tokens->buffer[0] == '!'){
        tokens->n_tokens[n_tok_count++] = tokens->buffer;
    }
    else{
        tokens->tokens[tok_count++] = tokens->buffer;
    }
    c = tokens->buffer;

    for (i = 1; i < num_tokens; i++) {
        /* Find next separator */
        found = strchr(c, separator);
        if (found == NULL) {
            break;
        }

        /* Replace it with a string terminator */
        *found = '\0';

        /* The next token starts in the next byte */
        c = found + 1;

        /* If we did not reach the end of the chain yet, set the next token */
        if (*c != '\0') {
            if(*c == '!'){
                tokens->n_tokens[n_tok_count++] = c+1;
            }
            else{
                tokens->tokens[tok_count++] = c;
            }
        } else {
            break;
        }
    }

    return tokens;

error:
    ssh_tokens_free(tokens);
    return NULL;
}

/**
 * @internal
 *
 * @brief given a string text and a pattern, checks if they match
 *  pattern recognises the following characters :
 *  ? => matches exactly one character
 *  * => matches with zero or more characters in a row 
 *  
 *  Example : aes* would match with all the aes algorithms 
 *                                  such as aes128-ctr, aes192-ctr etc.,
 *            aes1??-ctr would match with aes128-ctr and aes192-ctr
 *      
 *
 * @param[in] text      string to be matched           example : aes128-ctr
 * @param[in] pattern   string to be matched against   example : aes*
 *
 * @return  1 if text matches pattern
 *          0 if text does NOT match the pattern
 *         -1 if some error occurs 
 */
int wildcard_matching(const char * text, const char * pattern)
{
    int match;
    size_t str_len = strlen(text);
    size_t pat_len = strlen(pattern);
    bool *dp = calloc(str_len + 1, sizeof(bool));
    if (dp == NULL) {
        return -1;
    }
    // prev stores if the strings untill pat_it and str_it - 1 have matched
    int prev = 1, temp;
    dp[0] = 1;
    for (int pat_it = 0; pat_it < pat_len; pat_it++) {
        if (pattern[pat_it] != '*') {
            dp[0] = 0;
        }
        for (int str_it = 1; str_it < str_len + 1; str_it++) {
            temp = dp[str_it];
            if (pattern[pat_it] == '*') {
                dp[str_it] = dp[str_it - 1] || dp[str_it];
            }
            else if (pattern[pat_it] == '?' 
                            || pattern[pat_it] == text[str_it - 1]) {
                dp[str_it] = prev;
            }
            else {
                dp[str_it] = 0;
            }
            prev = temp;
        }
        prev = dp[0];
    }

    if (dp[str_len] != 0) {
        match = 1;
    }
    else {
        match = 0;
    }

    SAFE_FREE(dp);
    
    return match;
}

/**
 * @internal
 *
 * @brief Given two strings, the first containing a list of available tokens and
 * the second containing a list of tokens to be searched ordered by preference,
 * returns a copy of the first preferred token present in the available list.
 *
 * @param[in] available_list    The list of available tokens
 * @param[in] preferred_list    The list of tokens to search, ordered by
 * preference
 *
 * @return  A newly allocated copy of the token if found; 
 *          NULL otherwise (no token found or error occurred)    
 */
char *ssh_find_matching(const char *available_list,
                        const char *preferred_list)
{
    struct ssh_tokens_st *a_tok = NULL, *n_tok ,*p_tok = NULL;

    int i, j;
    char *ret = NULL;

    if ((available_list == NULL) || (preferred_list == NULL)) {
        return NULL;
    }

    a_tok = ssh_tokenize(available_list, ',');
    if (a_tok == NULL) {
        return NULL;
    }

    p_tok = ssh_tokenize(preferred_list, ',');
    if (p_tok == NULL) {
        goto out;
    }

    for (i = 0; p_tok->tokens[i]; i++) {
        for (j = 0; a_tok->tokens[j]; j++) {
            if (strcmp(a_tok->tokens[j], p_tok->tokens[i]) == 0) {
                ret = strdup(a_tok->tokens[j]);
                goto out;
            }
        }
    }

out:
    ssh_tokens_free(a_tok);
    ssh_tokens_free(p_tok);
    return ret;
}

/**
 * @internal
 *
 * @brief Given two strings, the first containing a list of available tokens and
 * the second containing a list of tokens to be searched ordered by preference,
 * returns a list of all matching tokens ordered by preference.
 *
 * @param[in] available_list    The list of available tokens
 * @param[in] preferred_list    The list of patterns to search and ignore.
 *                              Tokens to search for are ordered by preference.
 *
 * patterns to ignore should start with '!'
 * 
 * Example: 1.
 *            !aes* => ignores all tokens which start with aes
 *            !aes  => ignores only the token "aes" 
 * 
 * 
 * @return  A newly allocated string containing the list of all matching tokens;
 * NULL otherwise
 */
char *ssh_find_all_matching(const char *available_list,
                            const char *preferred_list)
{
    struct ssh_tokens_st *a_tok = NULL, *p_tok = NULL, *n_tok = NULL;
    int i, j, k;
    char *ret = NULL;
    size_t max, len, pos = 0;
    bool match;

    if ((available_list == NULL) || (preferred_list == NULL)) {
        return NULL;
    }

    max = MAX(strlen(available_list), strlen(preferred_list));

    ret = calloc(1, max + 1);
    if (ret == NULL) {
        return NULL;
    }

    a_tok = ssh_tokenize(available_list, ',');
    if (a_tok == NULL) {
        SAFE_FREE(ret);
        goto out;
    }

    p_tok = ssh_tokenize(preferred_list, ',');
    if (p_tok == NULL) {
        SAFE_FREE(ret);
        goto out;
    }

    for (i = 0; p_tok->tokens[i] ; i++) {
        for (j = 0; a_tok->tokens[j]; j++) {
            match = wildcard_matching(a_tok->tokens[j], p_tok->tokens[i]);
            if (match == -1) {
                // signifies error in wildcard_matching function
                return NULL;
            } 
            else if (match) {
                for (k = 0; p_tok->n_tokens[k]; k++) {
                    bool n_match = wildcard_matching(a_tok->tokens[j]
                                                    ,p_tok->n_tokens[k]);
                    if (n_match) {
                        match = false;
                    }
                }
            }
            if (match) {
                if (pos != 0) {
                    ret[pos] = ',';
                    pos++;
                }

                len = strlen(a_tok->tokens[j]);
                memcpy(&ret[pos], a_tok->tokens[j], len);
                pos += len;
                ret[pos] = '\0';
            }
        }
    }

    if (ret[0] == '\0') {
        SAFE_FREE(ret);
    }

out:
    ssh_tokens_free(a_tok);
    ssh_tokens_free(p_tok);
    return ret;
}

/**
 * @internal
 *
 * @brief Given a string containing a list of elements, remove all duplicates
 * and return in a newly allocated string.
 *
 * @param[in] list  The list to be freed of duplicates
 *
 * @return  A newly allocated copy of the string free of duplicates; NULL in
 * case of error.
 */
char *ssh_remove_duplicates(const char *list)
{
    struct ssh_tokens_st *tok = NULL;

    size_t i, j, num_tokens, max_len;
    char *ret = NULL;
    bool *should_copy = NULL, need_comma = false;

    if (list == NULL) {
        return NULL;
    }

    /* The maximum number of tokens is the size of the list */
    max_len = strlen(list);
    if (max_len == 0) {
        return NULL;
    }

    /* Add space for ending '\0' */
    max_len++;

    tok = ssh_tokenize(list, ',');
    if ((tok == NULL) || (tok->tokens == NULL) || (tok->tokens[0] == NULL)) {
        goto out;
    }

    should_copy = calloc(1, max_len);
    if (should_copy == NULL) {
        goto out;
    }

    if (strlen(tok->tokens[0]) > 0) {
        should_copy[0] = true;
    }

    for (i = 1; tok->tokens[i]; i++) {
        for (j = 0; j < i; j++) {
            if (strcmp(tok->tokens[i], tok->tokens[j]) == 0) {
                /* Found a duplicate; do not copy */
                should_copy[i] = false;
                break;
            }
        }

        /* No matching token before */
        if (j == i) {
            /* Only copy if it is not an empty string */
            if (strlen(tok->tokens[i]) > 0) {
                should_copy[i] = true;
            } else {
                should_copy[i] = false;
            }
        }
    }

    num_tokens = i;

    ret = calloc(1, max_len);
    if (ret == NULL) {
        goto out;
    }

    for (i = 0; i < num_tokens; i++) {
        if (should_copy[i]) {
            if (need_comma) {
                strncat(ret, ",", (max_len - strlen(ret) - 1));
            }
            strncat(ret, tok->tokens[i], (max_len - strlen(ret) - 1));
            need_comma = true;
        }
    }

    /* If no comma is needed, nothing was copied */
    if (!need_comma) {
        SAFE_FREE(ret);
    }

out:
    SAFE_FREE(should_copy);
    ssh_tokens_free(tok);
    return ret;
}

/**
 * @internal
 *
 * @brief Given two strings containing lists of tokens, return a newly
 * allocated string containing all the elements of the first list appended with
 * all the elements of the second list, without duplicates. The order of the
 * elements will be preserved.
 *
 * @param[in] list             The first list
 * @param[in] appended_list    The list to be appended
 *
 * @return  A newly allocated copy list containing all the elements of the
 * kept_list appended with the elements of the appended_list without duplicates;
 * NULL in case of error.
 */
char *ssh_append_without_duplicates(const char *list,
                                    const char *appended_list)
{
    size_t concat_len = 0;
    char *ret = NULL, *concat = NULL;
    int rc = 0;

    if (list != NULL) {
        concat_len = strlen(list);
    }

    if (appended_list != NULL) {
        concat_len += strlen(appended_list);
    }

    if (concat_len == 0) {
        return NULL;
    }

    /* Add room for ending '\0' and for middle ',' */
    concat_len += 2;
    concat = calloc(1, concat_len);
    if (concat == NULL) {
        return NULL;
    }

    rc = snprintf(concat, concat_len, "%s%s%s",
                  list == NULL ? "" : list,
                  list == NULL ? "" : ",",
                  appended_list == NULL ? "" : appended_list);
    if (rc < 0) {
        SAFE_FREE(concat);
        return NULL;
    }

    ret = ssh_remove_duplicates(concat);

    SAFE_FREE(concat);

    return ret;
}

/**
 * @internal
 *
 * @brief Given two strings containing lists of tokens, return a newly
 * allocated string containing the elements of the first list without the
 * elements of the second list. The order of the elements will be preserved.
 *
 * @param[in] list             The first list
 * @param[in] remove_list      The list to be removed
 *
 * @return  A newly allocated copy list containing elements of the
 * list without the elements of remove_list; NULL in case of error.
 */
char *ssh_remove_all_matching(const char *list,
                              const char *remove_list)
{
    struct ssh_tokens_st *l_tok = NULL, *r_tok = NULL;
    int i, j, cmp;
    char *ret = NULL;
    size_t len, pos = 0;
    bool exclude;

    if ((list == NULL)) {
        return NULL;
    }
    if (remove_list == NULL) {
        return strdup (list);
    }

    l_tok = ssh_tokenize(list, ',');
    if (l_tok == NULL) {
        goto out;
    }

    r_tok = ssh_tokenize(remove_list, ',');
    if (r_tok == NULL) {
        goto out;
    }

    ret = calloc(1, strlen(list) + 1);
    if (ret == NULL) {
        goto out;
    }

    for (i = 0; l_tok->tokens[i]; i++) {
        exclude = false;
        for (j = 0; r_tok->tokens[j]; j++) {
            cmp = strcmp(l_tok->tokens[i], r_tok->tokens[j]);
            if (cmp == 0) {
                exclude = true;
                break;
            }
        }
        if (exclude == false) {
            if (pos != 0) {
                ret[pos] = ',';
                pos++;
            }

            len = strlen(l_tok->tokens[i]);
            memcpy(&ret[pos], l_tok->tokens[i], len);
            pos += len;
        }
    }

    if (ret[0] == '\0') {
        SAFE_FREE(ret);
    }

out:
    ssh_tokens_free(l_tok);
    ssh_tokens_free(r_tok);
    return ret;
}

/**
 * @internal
 *
 * @brief Given two strings containing lists of tokens, return a newly
 * allocated string containing all the elements of the first list prefixed at
 * the beginning of the second list, without duplicates.
 *
 * @param[in] list             The first list
 * @param[in] prefixed_list    The list to use as a prefix
 *
 * @return  A newly allocated list containing all the elements
 * of the list prefixed with the elements of the prefixed_list without
 * duplicates; NULL in case of error.
 */
char *ssh_prefix_without_duplicates(const char *list,
                                    const char *prefixed_list)
{
    size_t concat_len = 0;
    char *ret = NULL, *concat = NULL;
    int rc = 0;

    if (list != NULL) {
        concat_len = strlen(list);
    }

    if (prefixed_list != NULL) {
        concat_len += strlen(prefixed_list);
    }

    if (concat_len == 0) {
        return NULL;
    }

    /* Add room for ending '\0' and for middle ',' */
    concat_len += 2;
    concat = calloc(concat_len, 1);
    if (concat == NULL) {
        return NULL;
    }

    rc = snprintf(concat, concat_len, "%s%s%s",
                  prefixed_list == NULL ? "" : prefixed_list,
                  prefixed_list == NULL ? "" : ",",
                  list == NULL ? "" : list);
    if (rc < 0) {
        SAFE_FREE(concat);
        return NULL;
    }

    ret = ssh_remove_duplicates(concat);

    SAFE_FREE(concat);

    return ret;
}
