// Copyright 2026 NeuralTrust
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package mcp

import "math/bits"

// What a request asks to do, and what a tool does.
//
// A request says what it wants done with a verb ("schedule a meeting", "who is
// on call", "borra la tarea") and a tool says what it does with the verb in its
// name (create_event, list_oncalls, delete_task). When both say, a tool that
// does what was asked counts for more and one that does something else counts
// for less. That puts create_event over list_events for "schedule a meeting",
// and keeps a tool that removes something under the tools that read for "show
// my tasks".
//
// It only reorders what the words matched: a tool the query's words do not
// match is not brought in by its verb.

// action is a kind of thing a request asks for or a tool does. A word can mean
// more than one (a tool that saves creates or updates).
type action uint8

const (
	actionRead action = 1 << iota
	actionSearch
	actionCreate
	actionUpdate
	actionDelete
	actionSend
)

const (
	// intentBoost is how much more a tool counts when it does all the request
	// asks for; one that does part of it gets part of the boost.
	intentBoost = 0.6
	// intentPenalty is what a tool that does something else counts for.
	intentPenalty = 0.7
	// destructivePenalty is what a tool that removes or ends something counts
	// for when the request only reads: it must never come first for a read.
	destructivePenalty = 0.3
)

// verbList is a list of words and the action they say.
type verbList struct {
	words  string
	action action
}

// requestVerbs are the words a request says what it wants with, as
// normalizeToken leaves them. Question words read. Nouns that double as verbs
// ("email", "file", "log") are left out: a request that starts with one is as
// often naming a thing as asking for something.
var requestVerbs = verbTable([]verbList{
	{"list get show see view read fetch look check browse display review give " +
		"what which who where when how " +
		"ver mostrar muestra muestrame listar obtener leer consultar revisar dame " +
		"que cual quien donde cuando como", actionRead},
	{"search find lookup locate query buscar busca encontrar", actionSearch | actionRead},
	{"create new add write draft make schedule book " +
		"crear crea nuevo nueva anadir agregar redactar escribir programar agendar hacer generar", actionCreate},
	{"open abrir abre", actionCreate | actionRead},
	{"upload subir", actionCreate},
	{"invite invitar", actionCreate | actionSend},
	{"save guardar", actionCreate | actionUpdate},
	{"post publish publicar announce", actionSend | actionCreate},
	{"update edit change modify move rename mark set reschedule transition complete finish close " +
		"resolve acknowledge ack assign approve accept decline " +
		"actualizar editar cambiar modificar mover marcar cerrar resolver completar asignar aceptar rechazar reprogramar", actionUpdate},
	{"delete remove cancel trash erase archive unsubscribe " +
		"borrar borra eliminar elimina cancelar quitar archivar", actionDelete},
	{"send reply notify tell share forward ping " +
		"enviar envia responder avisar notificar decir contestar compartir", actionSend},
})

// toolVerbs are the verbs tools are named with.
var toolVerbs = verbTable([]verbList{
	{"list get read fetch show view describe retrieve download export check count browse whoami suggest", actionRead},
	{"search find query lookup", actionSearch | actionRead},
	{"create add new insert upload write make draft generate copy duplicate schedule book log open start " +
		"import invite", actionCreate},
	{"save upsert", actionCreate | actionUpdate},
	{"update edit set modify change move rename mark complete close resolve manage transition assign " +
		"finalize merge label restore enable disable toggle patch apply accept approve reject resume reopen", actionUpdate},
	{"respond", actionUpdate | actionSend},
	{"post publish", actionSend | actionCreate},
	{"send reply notify share forward", actionSend},
	{"delete remove trash cancel destroy drop purge revoke unshare retire clear reset pause archive " +
		"spam unsubscribe", actionDelete},
})

// verbTable maps each word to what it says. A word in more than one list says
// all of them.
func verbTable(lists []verbList) map[string]action {
	out := make(map[string]action)
	for _, list := range lists {
		for _, word := range splitWords(list.words) {
			out[normalizeToken(word)] |= list.action
		}
	}
	return out
}

func splitWords(text string) []string {
	var out []string
	start := -1
	for i, r := range text {
		if r == ' ' {
			if start >= 0 {
				out = append(out, text[start:i])
				start = -1
			}
			continue
		}
		if start < 0 {
			start = i
		}
	}
	if start >= 0 {
		out = append(out, text[start:])
	}
	return out
}

// requestAction is what a query asks for: the first word of it that says.
func requestAction(words []string) action {
	for _, word := range words {
		if act, ok := requestVerbs[word]; ok {
			return act
		}
	}
	return 0
}

// toolAction is what a tool does: the first verb in its name past the
// server's own words, so a server named after a verb is not read as one.
func toolAction(nameWords []string, server map[string]float64) action {
	for _, word := range nameWords {
		if server[word] > 0 {
			continue
		}
		if act, ok := toolVerbs[word]; ok {
			return act
		}
	}
	return 0
}

// intentFactor is what a tool's score is multiplied by for what it does
// against what the request asks for. Either one unsaid leaves it alone.
func intentFactor(request, tool action) float64 {
	if request == 0 || tool == 0 {
		return 1
	}
	shared := request & tool
	if shared == 0 {
		if request&^(actionRead|actionSearch) == 0 && tool&actionDelete != 0 {
			return destructivePenalty
		}
		return intentPenalty
	}
	return 1 + intentBoost*float64(bits.OnesCount8(uint8(shared)))/float64(bits.OnesCount8(uint8(request)))
}
