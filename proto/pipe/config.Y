/*
 *	BIRD -- Table-to-Table Protocol Configuration
 *
 *	(c) 1999 Martin Mares <mj@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

CF_HDR

#include "proto/pipe/pipe.h"
#include "nest/route.h"

CF_DEFINES

#define PIPE_CFG ((struct pipe_config *) this_proto)
#define AGGR_ITEM_ALLOC     cfg_allocz(sizeof(struct aggr_item))

CF_DECLS
%type <ai> aggr_item aggr_list
%type <ail> aggr_definition

CF_KEYWORDS(PIPE, PEER, TABLE, AGGREGATED, IMPORT, EXPORT, AGGREGATE)

CF_GRAMMAR

proto: pipe_proto '}' { this_channel = NULL; }  ;

pipe_proto_start: proto_start PIPE
{
  this_proto = proto_config_new(&proto_pipe, $1);
}
proto_name
{
  this_channel = proto_cf_main_channel(this_proto);
  if (!this_channel) {
    this_channel = channel_config_new(NULL, NULL, 0, this_proto);
    this_channel->in_filter = FILTER_ACCEPT;
    this_channel->out_filter = FILTER_ACCEPT;
  }
};

/* | pipe_proto MERGE PATHS IMPORT bool kern_mp_limit { PIPE_CFG->merge_limit_import = $5 ? $6 : 0; } */
/* | pipe_proto MERGE PATHS EXPORT bool kern_mp_limit { PIPE_CFG->merge_limit_export = $5 ? $6 : 0; } */

aggr_list:
   aggr_item
 | aggr_list ',' aggr_item {
       $$ = $3;
       $$->next = $1;
   }
 ;

aggr_item:
   '(' term ')' {
       $$ = AGGR_ITEM_ALLOC;
       $$->intern.type = AGGR_ITEM_TERM;
       $$->intern.line = f_linearize($2, 1);
    }
  | CF_SYM_KNOWN {
      switch ($1->class) {
        case SYM_ATTRIBUTE:
          $$ = AGGR_ITEM_ALLOC;
          $$->intern.type = AGGR_ITEM_DYNAMIC_ATTR;
          $$->intern.da = *$1->attribute;
          break;
        case SYM_CONSTANT_RANGE:
          break;
        default:
          cf_error("Can't aggregate on symbol type %s.", cf_symbol_class_name($1));
      }
    }
  | dynamic_attr {
      $$ = AGGR_ITEM_ALLOC;
      $$->intern.type = AGGR_ITEM_DYNAMIC_ATTR;
      $$->intern.da = $1;
    }
  | static_attr {
      $$ = AGGR_ITEM_ALLOC;
      $$->intern.type = AGGR_ITEM_STATIC_ATTR;
      $$->intern.sa = $1;
    }
  ;

aggr_definition:
    AGGREGATE ON aggr_list {
      _Bool net_present = 0;
      int count = 0;

      for (const struct aggr_item *ai = $3; ai; ai = ai->next) {
        if (ai->intern.type == AGGR_ITEM_STATIC_ATTR && ai->intern.sa.sa_code == SA_NET) {
          net_present = 1;
        }
        count++;
      }

     if (!net_present) {
       cf_error("'NET' must be present");
     }

     size_t allocated = sizeof(struct aggr_item_linearized) + sizeof(struct aggr_item_internal) * count;
     struct aggr_item_linearized *linear = cfg_allocz(allocated);
     linear->count = count;

     const struct aggr_item *ai = $3;

     for (int i = 0; i < count; i++) {
       linear->items[i] = ai->intern;
       ai = ai->next;
     }
     $$ = linear;
  }
  ;

pipe_proto:
   pipe_proto_start '{'
 | pipe_proto proto_item ';'
 | pipe_proto channel_item_ ';'
 | pipe_proto PEER TABLE rtable ';' { PIPE_CFG->peer = $4; }
 | pipe_proto MERGE PATHS IMPORT bool kern_mp_limit { PIPE_CFG->config_import.limit = $5 ? $6 : 0; PIPE_CFG->config_import.use_aggregator = 0; }
 | pipe_proto MERGE PATHS EXPORT bool kern_mp_limit { PIPE_CFG->config_export.limit = $5 ? $6 : 0; PIPE_CFG->config_export.use_aggregator = 0; }
 | pipe_proto IMPORT AGGREGATED bool kern_mp_limit  { PIPE_CFG->config_import.limit = $4 ? $5 : 0; PIPE_CFG->config_import.use_aggregator = 1; }
 | pipe_proto EXPORT AGGREGATED bool kern_mp_limit  { PIPE_CFG->config_export.limit = $4 ? $5 : 0; PIPE_CFG->config_export.use_aggregator = 1; }
 | pipe_proto IMPORT aggr_definition { PIPE_CFG->ai_import = $3; }
 | pipe_proto EXPORT aggr_definition { PIPE_CFG->ai_export = $3; }
 ;

CF_CODE

CF_END
