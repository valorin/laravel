<?php

use Illuminate\Auth\Passwords\PasswordBroker;
use Illuminate\Auth\Passwords\TokenRepositoryInterface;
use Illuminate\Foundation\Inspiring;
use Illuminate\Support\Benchmark;
use Illuminate\Support\Facades\Artisan;
use \App\Models\User;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Password;

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

Artisan::command('timing-attack:sendResetLink {iterations}', function ($iterations) {

    $user = User::firstOrCreate([
        'email' => 'stephen@valorinsecurity.com',
    ], [
        'name' => 'Stephen',
        'password' => bcrypt('password'),
    ]);

    $tokens = new class implements TokenRepositoryInterface
    {
        public function create(\Illuminate\Contracts\Auth\CanResetPassword $user)
        {
            return false;
        }

        public function exists(\Illuminate\Contracts\Auth\CanResetPassword $user, $token)
        {
            return false;
        }

        public function recentlyCreatedToken(\Illuminate\Contracts\Auth\CanResetPassword $user)
        {
            return false;
        }

        public function delete(\Illuminate\Contracts\Auth\CanResetPassword $user)
        {
            return false;
        }

        public function deleteExpired()
        {
            return false;
        }
    };

    $broker = new PasswordBroker(
        $tokens,
        Auth::createUserProvider('users'),
        app('events'),
        //timeboxDuration: config('auth.timebox_duration'),
    );

    Benchmark::dd([
        'Known Email' => function () use ($user, $broker) {
            return $broker->sendResetLink(['email' => $user->email]);
        },
        'Unknown Email' => function () use ($broker) {
            return $broker->sendResetLink(['email' => 'noone@test.com']);
        },
    ], $iterations);
});

Artisan::command('timing-attack:reset {iterations}', function ($iterations) {

    $user = User::firstOrCreate([
        'email' => 'stephen@valorinsecurity.com',
    ], [
        'name' => 'Stephen',
        'password' => bcrypt('password'),
    ]);

    $tokens = new class implements TokenRepositoryInterface
    {
        public function create(\Illuminate\Contracts\Auth\CanResetPassword $user)
        {
            return false;
        }

        public function exists(\Illuminate\Contracts\Auth\CanResetPassword $user, $token)
        {
            return false;
        }

        public function recentlyCreatedToken(\Illuminate\Contracts\Auth\CanResetPassword $user)
        {
            return false;
        }

        public function delete(\Illuminate\Contracts\Auth\CanResetPassword $user)
        {
            return false;
        }

        public function deleteExpired()
        {
            return false;
        }
    };

    $broker = new PasswordBroker(
        $tokens,
        Auth::createUserProvider('users'),
        app('events'),
        //timeboxDuration: config('auth.timebox_duration'),
    );

    $callback = fn () => null;

    Benchmark::dd([
        'Known Email' => function () use ($user, $broker, $callback) {
            return $broker->reset(['email' => $user->email, 'token' => 'abc123'], $callback);
        },
        'Unknown Email' => function () use ($broker, $callback) {
            return $broker->reset(['email' => 'noone@test.com', 'token' => 'abc123'], $callback);
        },
    ], $iterations);
});
