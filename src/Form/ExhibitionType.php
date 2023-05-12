<?php

namespace App\Form;

use App\Entity\User;
use App\Entity\Exhibition;
use Doctrine\ORM\EntityRepository;
use Symfony\Component\Form\AbstractType;
use Symfony\Component\Form\FormBuilderInterface;
use Symfony\Bridge\Doctrine\Form\Type\EntityType;
use Symfony\Component\OptionsResolver\OptionsResolver;
use Symfony\Component\Form\Extension\Core\Type\TextType;
use Symfony\Component\Form\Extension\Core\Type\TextareaType;

class ExhibitionType extends AbstractType
{
    public function buildForm(FormBuilderInterface $builder, array $options): void
    {
        $builder
            ->add('title', TextType::class,
            [
                'label' => 'Titre de l\'exposition *',
                'help' => 'Le titre ne doit pas dépasser 255 caractères',
            ]
            )
            ->add('description', TextareaType::class,
            [
                'label' => 'Description de l\'exposition',
                'empty_data' => null
            ])
            ->add('artist', EntityType::class,
            [
                'label' => 'Artiste *',
                'class' => User::class,
                'query_builder' => function(EntityRepository $er)
                {
                    return $er->createQueryBuilder('u')
                    ->where('u.roles LIKE :role')
                    ->setParameter('role', '%"'.'ROLE_ARTIST'.'"%');
                },
                'choice_label' => function (User $user)
                {
                    if($user->getNickname() === null){

                        return $user->getFullName();
                    }
                    
                    return $user->getNickname();
                    
                },
                'placeholder' => 'Choisissez un(e) artiste ', 
                'attr' => [
                    'class'=> 'form-select'
                ]               
            ])
        ;
    }

    public function configureOptions(OptionsResolver $resolver): void
    {
        $resolver->setDefaults([
            'data_class' => Exhibition::class,
        ]);
    }
}
