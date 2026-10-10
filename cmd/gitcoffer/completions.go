package main

// Shell completion scripts for the gitcoffer CLI, one per supported
// shell. They are static (no dynamic flag introspection): the command
// surface is small and stable, and static scripts work everywhere
// without dependencies.

import (
	"flag"
	"fmt"
	"os"
)

const bashCompletion = `# bash completion for gitcoffer
_gitcoffer() {
	local commands="init status rekey key gc fsck doctor export-bundle version completion"
	local gc_opts="--prune" key_opts="--keyfile" ver_opts="--json" global_opts="-h --help --json"
	if [[ $COMP_CWORD -eq 1 ]]; then
		COMPREPLY=( $(compgen -W "$commands" -- "$2") )
		return
	fi
	local prev=${COMP_WORDS[COMP_CWORD-1]}
	case ${COMP_WORDS[1]} in
		gc)       COMPREPLY=( $(compgen -W "$gc_opts" -- "$2") ) ;;
		key)      [[ $COMP_CWORD -eq 2 ]] && COMPREPLY=( $(compgen -W "add remove list" -- "$2") ) || COMPREPLY=( $(compgen -W "$key_opts" -- "$2") ) ;;
		version)  COMPREPLY=( $(compgen -W "$ver_opts" -- "$2") ) ;;
		*)        COMPREPLY=( $(compgen -W "$global_opts" -- "$2") ) ;;
	esac
}
complete -F _gitcoffer gitcoffer
`

const zshCompletion = `#compdef gitcoffer
# zsh completion for gitcoffer
_gitcoffer() {
	local -a commands
	commands=(
		'init:create a new encrypted vault'
		'status:inspect a vault'
		'rekey:change the passphrase of a key slot'
		'key:manage key slots'
		'gc:report or remove reclaimable space'
		'fsck:verify every structure of the vault'
		'doctor:check the environment and the vault'
		'export-bundle:export the vault as a plain git bundle'
		'version:print the build version'
	)
	_arguments \
		'(-h --help)'{-h,--help}'[show help]' \
		'1: :->command' \
		'*:: :->args'
	case $state in
		command)
			_describe -t commands 'gitcoffer command' commands
			;;
		args)
			case $words[1] in
				gc) _values 'option' --prune ;;
				key) [[ $CURRENT -eq 3 ]] && _values 'subcommand' add remove list || _files ;;
				version) _values 'option' --json ;;
				*) _files ;;
			esac
			;;
	esac
}
_gitcoffer "$@"
`

const fishCompletion = `# fish completion for gitcoffer
complete -c gitcoffer -n '__fish_use_subcommand' -a init -d 'create a new encrypted vault'
complete -c gitcoffer -n '__fish_use_subcommand' -a status -d 'inspect a vault'
complete -c gitcoffer -n '__fish_use_subcommand' -a rekey -d 'change the passphrase of a key slot'
complete -c gitcoffer -n '__fish_use_subcommand' -a key -d 'manage key slots'
complete -c gitcoffer -n '__fish_use_subcommand' -a gc -d 'report or remove reclaimable space'
complete -c gitcoffer -n '__fish_use_subcommand' -a fsck -d 'verify every structure of the vault'
complete -c gitcoffer -n '__fish_use_subcommand' -a doctor -d 'check the environment and the vault'
complete -c gitcoffer -n '__fish_use_subcommand' -a export-bundle -d 'export the vault as a plain git bundle'
complete -c gitcoffer -n '__fish_use_subcommand' -a version -d 'print the build version'
complete -c gitcoffer -n '__fish_seen_subcommand_from gc' -l prune -d 'actually delete what gc finds'
complete -c gitcoffer -n '__fish_seen_subcommand_from key; and not __fish_seen_subcommand_from add; and not __fish_seen_subcommand_from remove; and not __fish_seen_subcommand_from list' -a 'add remove list'
complete -c gitcoffer -n '__fish_seen_subcommand_from version' -l json -d 'print JSON'
`

const powershellCompletion = `# powershell completion for gitcoffer
Register-ArgumentCompleter -CommandName gitcoffer -ScriptBlock {
	param($wordToComplete, $commandAst, $cursorPosition)
	$commands = 'init','status','rekey','key','gc','fsck','doctor','export-bundle','version'
	if ($commandAst.CommandExtent.EndColumnPosition -le ($wordToComplete.Length + 6)) {
		$commands | Where-Object { $_ -like "$wordToComplete*" } |
			ForEach-Object { [System.Management.Automation.CompletionResult]::new($_) }
	}
}
`

func completionCmd(args []string) error {
	fs := flag.NewFlagSet("completion", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: gitcoffer completion <bash|zsh|fish|powershell>")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		fs.Usage()
		os.Exit(2)
	}
	var script string
	switch shell := fs.Arg(0); shell {
	case "bash":
		script = bashCompletion
	case "zsh":
		script = zshCompletion
	case "fish":
		script = fishCompletion
	case "powershell":
		script = powershellCompletion
	default:
		return fmt.Errorf("unknown shell %q — supported: bash, zsh, fish, powershell", shell)
	}
	fmt.Print(script)
	return nil
}
