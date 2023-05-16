<?php

namespace App\Controller\Back;

use App\Entity\User;
use App\Form\UserType;
use App\Service\MySlugger;
use App\Repository\UserRepository;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;

/**
 * @Route("/user")
 */
class UserController extends AbstractController
{
    /**
     * Display all users
     * Process sorting depending on role
     * 
     * @param UserRepository $userRepository
     * @param Request $request
     * @return Response
     * @Route("/", name="app_user_index", methods={"GET", "POST"})
     */
    public function index(UserRepository $userRepository, Request $request): Response
    {
        $role = $request->request->get('role');

        if(isset($role) && $role != "ROLES"){

            $users = $userRepository->getUsersListOnRole($role);
        }else if($role === "ROLES" || !isset($role)){
            
            $users = $userRepository->findAll();
        }
      
        return $this->render('user/index.html.twig', [
            'users' => $users
        ]);
    }

    /**
     * Display new form and process new form
     * 
     * @param Request $request
     * @param UserRepository $userRepository
     * @param UserPasswordHasherInterface $passwordHasher
     * @return Response
     * @Route("/new", name="app_user_new", methods={"GET", "POST"})
     */
    public function new(Request $request, UserRepository $userRepository, UserPasswordHasherInterface $passwordHasher): Response
    {
        // create new entity and new form
        $user = new User();
        $form = $this->createForm(UserType::class, $user);
        $form->handleRequest($request);

        //if form is submited
        if ($form->isSubmitted() && $form->isValid()) {
            
            //hashing the password
            $user->setPassword($passwordHasher->hashPassword($user, $user->getPassword()));
            $userRepository->add($user, true);

            // flash messages
            $this->addFlash('success', 'L\'utilisateur a été ajouté');

            //redirection
            return $this->redirectToRoute('app_user_index', [], Response::HTTP_SEE_OTHER);
        }

        //else return twig and new form
        return $this->renderForm('user/new.html.twig', [
            'user' => $user,
            'form' => $form,
        ]);
    }

    /**
     * Display an entity
     * 
     * @param User|null $user 
     * @return Response
     * @Route("/{id}", name="app_user_show", methods={"GET"}, requirements={"id"="\d+"})
     */
    public function show(User $user = null): Response
    {
        //404?
        if ($user === null) {
            return $this->json(['error' => 'Utilisateur non trouvé.'], Response::HTTP_NOT_FOUND);
        }

        return $this->render('user/show.html.twig', [
            'user' => $user,
        ]);
    }

    /**
     * Display edit form and process edit form
     * 
     * @param Request $request
     * @param UserRepository $userRepository
     * @param User|null $user 
     * @return Response
     * @Route("/{id}/edit", name="app_user_edit", methods={"GET", "POST"}, requirements={"id"="\d+"})
     */
    public function edit(Request $request, User $user = null, UserRepository $userRepository): Response
    {
        //404?
        if ($user === null) {
            return $this->json(['error' => 'Utilisateur non trouvé.'], Response::HTTP_NOT_FOUND);
        }

        //create edit form
        $form = $this->createForm(UserType::class, $user);
        $form->handleRequest($request);

        // if form is submited
        if ($form->isSubmitted() && $form->isValid()) {

            $userRepository->add($user, true);

            //flash messages
            $this->addFlash('success', 'L\'utilisateur a été modifié');

            //redirection
            return $this->redirectToRoute('app_user_index', [], Response::HTTP_SEE_OTHER);
        }

        //else return twig and edit form
        return $this->renderForm('user/edit.html.twig', [
            'user' => $user,
            'form' => $form,
        ]);
    }

    /**
     * Delete item
     * 
     * @param Request $request
     * @param UserRepository $userRepository
     * @param User|null $user 
     * @return Response
     * @Route("/{id}", name="app_user_delete", methods={"POST"}, requirements={"id"="\d+"})
     */
    public function delete(Request $request, User $user = null, UserRepository $userRepository): Response
    {
        //404?
        if ($user === null) {
            return $this->json(['error' => 'Utilisateur non trouvé.'], Response::HTTP_NOT_FOUND);
        }

        //if token is valid
        if ($this->isCsrfTokenValid('delete' . $user->getId(), $request->request->get('_token'))) {
            //then remove entity
            $userRepository->remove($user, true);
        }

        //flash messages
        $this->addFlash('danger', 'L\'utilisateur a été supprimé');

        //redirection
        return $this->redirectToRoute('app_user_index', [], Response::HTTP_SEE_OTHER);
    }
}
