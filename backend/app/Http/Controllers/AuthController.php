<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\ValidationException;

class AuthController extends Controller
{

  /**
   * Validate the user login request.
   * @param Request $request
   * @return void
   */
  protected function validateLogin(Request $request)
  {
    $request->validate([
      'email' => 'required|string',
      'password' => 'required|string',
    ]);
  }

  public function login(Request $request): JsonResponse
  {
    $this->validateLogin($request);
    $user = User::where('email', $request->input('email'))->first();
    $password = $request->input('password');
    if (!$user || !Hash::check($password, $user->password)) {
      return response()->json(['Credential not found!, Please try again!'], 401);
    }

    $token = $user->createToken('myapptoken')->plainTextToken;
    $response = ['user' => $user, 'token' => $token];
    return response()->json(['response' => $response], 200);
  }

  public function register(Request $request): JsonResponse
  {
    $user = User::create([
      'name' => $request->input('name'),
      'email' => $request->input('email'),
      'password' => bcrypt($request->input('password')),
    ]);
    $token = $user->createToken('myapptoken')->plainTextToken;
    $response = ['user' => $user, 'token' => $token];
    return response()->json(['response' => $response], 200);
  }

  public function logout(Request $request): JsonResponse
  {
    $request->user()->currentAccessToken()->delete();
    return response()->json(['message' => 'Successfully logout!']);
  }
}
