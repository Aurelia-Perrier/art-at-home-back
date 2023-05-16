<?php

namespace App\Controller\Back;

use App\Entity\Exhibition;
use App\Form\ExhibitionType;
use App\Repository\ExhibitionRepository;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Console\Input\ArrayInput;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Console\Output\NullOutput;
use Symfony\Component\HttpKernel\KernelInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Bundle\FrameworkBundle\Console\Application;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;

/**
 * @Route("/exhibition")
 */
class ExhibitionController extends AbstractController
{
    /**
     * Display all active exhibitions
     * 
     * @param ExhibitionRepository $exhibitionRepository
     * @return Response
     * @Route("/", name="app_exhibition_index", methods={"GET"})
     */
    public function index(ExhibitionRepository $exhibitionRepository): Response
    {
        return $this->render('exhibition/index.html.twig', [
            'exhibitions' => $exhibitionRepository->findBy(['status' => 1], ['title' => 'ASC']),
        ]);
    }

    /**
     * Display add form and process form
     * 
     * @param Request $request
     * @param ExhibitionRepository $exhibitionRepository
     * @return Response
     * @Route("/new", name="app_exhibition_new", methods={"GET", "POST"})
     */
    public function new(Request $request, ExhibitionRepository $exhibitionRepository): Response
    {
        // create exhibition entity and create new form
        $exhibition = new Exhibition();
        $form = $this->createForm(ExhibitionType::class, $exhibition);
        $form->handleRequest($request);

        //if form is submited
        if ($form->isSubmitted() && $form->isValid()) {

            $exhibitionRepository->add($exhibition, true);

            // flash messages
            $this->addFlash('success', 'L\'exposition a été ajoutée');

            //redirection
            return $this->redirectToRoute('app_exhibition_index', [], Response::HTTP_SEE_OTHER);
        }

        //else return twig and display new form
        return $this->renderForm('exhibition/new.html.twig', [
            'exhibition' => $exhibition,
            'form' => $form,
        ]);
    }

    /**
     * Display exhibition entity
     * 
     * @param Exhibition|null $exhibition 
     * @return Response
     * @Route("/{id}", name="app_exhibition_show", methods={"GET"}, requirements={"id"="\d+"})
     */
    public function show(Exhibition $exhibition = null): Response
    {
        //404?
        if ($exhibition === null) {
            return $this->json(['error' => 'Exposition non trouvé.'], Response::HTTP_NOT_FOUND);
        }

        return $this->render('exhibition/show.html.twig', [
            'exhibition' => $exhibition,
        ]);
    }

    /**
     * Display edit form and process edit form
     * 
     * @param Request $request
     * @param Exhibition|null $exhibition
     * @param ExhibitionRepository $exhibitionRepository
     * @return Response
     * @Route("/{id}/edit", name="app_exhibition_edit", methods={"GET", "POST"}, requirements={"id"="\d+"})
     */
    public function edit(Request $request, Exhibition $exhibition = null, ExhibitionRepository $exhibitionRepository): Response
    {

        //404?
        if ($exhibition === null) {
            return $this->json(['error' => 'Exposition non trouvé.'], Response::HTTP_NOT_FOUND);
        }

        //create edit form
        $form = $this->createForm(ExhibitionType::class, $exhibition);
        $form->handleRequest($request);

        //if form is submited
        if ($form->isSubmitted() && $form->isValid()) {

            $exhibitionRepository->add($exhibition, true);

            //flash messages
            $this->addFlash('success', 'L\'exposition a été modifiée');

            //redirection
            return $this->redirectToRoute('app_exhibition_index', [], Response::HTTP_SEE_OTHER);
        }

        //else return twig and edit form
        return $this->renderForm('exhibition/edit.html.twig', [
            'exhibition' => $exhibition,
            'form' => $form,
        ]);
    }

    /**
     * Delete an exhibition item
     * 
     * @param Request $request
     * @param Exhibition|null $exhibition
     * @param ExhibitionRepository $exhibitionRepository
     * @return Response
     * @Route("/{id}", name="app_exhibition_delete", methods={"POST"}, requirements={"id"="\d+"})
     */
    public function delete(Request $request, Exhibition $exhibition = null, ExhibitionRepository $exhibitionRepository): Response
    {
        //404?
        if ($exhibition === null) {
            return $this->json(['error' => 'Exposition non trouvé.'], Response::HTTP_NOT_FOUND);
        }

        // if token is valid
        if ($this->isCsrfTokenValid('delete' . $exhibition->getId(), $request->request->get('_token'))) {

            //then remove item
            $exhibitionRepository->remove($exhibition, true);
        }

        // flash messages
        $this->addFlash('danger', 'L\'exposition a été supprimée');

        //redirection
        return $this->redirectToRoute('app_exhibition_index', [], Response::HTTP_SEE_OTHER);
    }

    /**
     * Get all inactive exhibition
     *
     * @param ExhibitionRepository $exhibitionRepository
     * @Route ("/archive", name="app_exhibitions_archive", methods={"GET"})
     */
    public function archiveExhibitions(ExhibitionRepository $exhibitionRepository)
    {
        //fetching exhibitions with status false
        $archiveExhibitions = $exhibitionRepository->findBy(['status' => 0]);

        return $this->render('exhibition/archive.html.twig', ['archiveExhibitions' => $archiveExhibitions]);
    }

    /**
     * Get related artworks to exhibition
     *
     * @param Request $request
     * @param Exhibition $exhibition
     * @Route ("/{id}/artworks", name="app_exhibitions_artworks", methods={"GET"}, requirements={"id"="\d+"})
     */
    public function artworksRelatedToExhibition(Exhibition $exhibition, Request $request)
    {
        //fetching related artworks 
        $relatedArtworks = $exhibition->getArtwork();

        //fetching the BASE URL
        $baseUrl = $request->getScheme() . '://' . $request->getHttpHost() . $request->getBasePath();

        return $this->render('exhibition/artworks_related.html.twig', ['relatedArtworks' => $relatedArtworks, 'exhibition' => $exhibition, 'baseUrl' => $baseUrl]);
    }

    /**
     * Executing command to check exhibitions status 
     *
     * @param KernelInterface $kernel
     * @return Response
     * @Route ("/command", name="app_exhibitions_command_check")
     */
    public function executeCommand(KernelInterface $kernel) : Response
    {
        // fetching symfony application
        $application = new Application($kernel);
        $application->setAutoExit(false);

        //selecting command
        $input = new ArrayInput([
            'command' => 'app:exhibitions:check',
        ]);

        //don't need output
        $output = new NullOutput();
        //running command
        $application->run($input, $output);

        //flash messages
        $this->addFlash('primary', 'La vérification a été effectuée');

        //redirection
        return new RedirectResponse($this->generateUrl('app_exhibition_index'));
    }
}
