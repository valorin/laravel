<?php

use Illuminate\Foundation\Inspiring;
use Illuminate\Support\Benchmark;
use Illuminate\Support\Facades\Artisan;
use \App\Models\User;
use Illuminate\Support\Facades\Auth;

Artisan::command('inspire', function () {
    $this->comment(Inspiring::quote());
})->purpose('Display an inspiring quote');



Artisan::command('timing-attack:attempt {iterations}', function ($iterations) {

    $user = User::firstOrCreate([
        'email' => 'stephen@valorinsecurity.com',
    ], [
        'name' => 'Stephen',
        'password' => bcrypt('password'),
    ]);

    $guard = Auth::guard();

    Benchmark::dd([
        // validate()
        'validate() -> Successful Login' => function () use ($user, $guard) {
            $guard->getTimebox()->dontReturnEarly();
            $guard->validate(['email' => $user->email, 'password' => 'password']);
        },
        'validate() -> Invalid Password' => function () use ($user, $guard) {
            $guard->getTimebox()->dontReturnEarly();
            $guard->validate(['email' => $user->email, 'password' => 'abc']);
        },
        'validate() -> Invalid Email' => function () use ($guard) {
            $guard->getTimebox()->dontReturnEarly();
            $guard->validate(['email' => 'noone@test.com', 'password' => 'abc']);
        },

        // attempt()
        'attempt() -> Successful Login' => function () use ($user, $guard) {
            $guard->getTimebox()->dontReturnEarly();
            $guard->attempt(['email' => $user->email, 'password' => 'password']);
        },
        'attempt() -> Invalid Password' => function () use ($user, $guard) {
            $guard->getTimebox()->dontReturnEarly();
            $guard->attempt(['email' => $user->email, 'password' => 'abc']);
        },
        'attempt() -> Invalid Email' => function () use ($guard) {
            $guard->getTimebox()->dontReturnEarly();
            $guard->attempt(['email' => 'noone@test.com', 'password' => 'abc']);
        },

        // attemptWhen()
        'attemptWhen() -> Successful Login' => function () use ($user, $guard) {
            $guard->getTimebox()->dontReturnEarly();
            $guard->attemptWhen(['email' => $user->email, 'password' => 'password']);
        },
        'attemptWhen() -> Invalid Password' => function () use ($user, $guard) {
            $guard->getTimebox()->dontReturnEarly();
            $guard->attemptWhen(['email' => $user->email, 'password' => 'abc']);
        },
        'attemptWhen() -> Invalid Email' => function () use ($guard) {
            $guard->getTimebox()->dontReturnEarly();
            $guard->attemptWhen(['email' => 'noone@test.com', 'password' => 'abc']);
        },
    ], $iterations);

});
