<?php

namespace PHPTerminalModulesFirewall;

use PHPTerminal\Modules;
use PHPTerminal\Terminal;

class Firewall extends Modules
{
    protected $terminal;

    protected $command;

    public function init(Terminal $terminal = null, $command) : object
    {
        $this->terminal = $terminal;

        $this->command = $command;

        return $this;
    }

    protected function showFirewall()
    {
        $this->terminal->addResponse('', 0, ['Firewall Details' => 'Hello world']);

        return true;
    }

    public function onInstall() : object
    {
        $this->terminal->config['modules']['firewall']['banner'] = 'PHPTerminal-modules-firewall is an firewall module for PHPTerminal to manage PHPFirewall library.';

        return $this;
    }

    public function getCommands() : array
    {
        return
            [
                [
                    "availableAt"   => "enable",
                    "command"       => "show firewall",
                    "description"   => "Show firewall modules.",
                    "function"      => "show"
                ]
            ];
    }
}